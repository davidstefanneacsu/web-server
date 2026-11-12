#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include <cstring>
#include "lib.h"
#include "utils.h"
#include <cassert>
#include <poll.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

std::map<int, struct connection *> cons;

struct pollfd data_fds[MAX_CONNECTIONS];
/* Used for timers per connection */
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;

int bdp_window_size = MAX_WINDOW_SIZE;
int timeout_interval_ms = 100;

// Helper to push one slot to the network
void transmit_packet(struct connection *con, int slot) {
    sendto(con->sockfd, con->send_buf[slot].data, con->send_buf[slot].len, 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
    con->send_buf[slot].sent = 1;
}

// Helper to fill the window from app_buf and send any unsent packets
void process_send_window(struct connection *con) {
    int current_window = con->recv_window;
    if (con->max_window_seq < current_window) {
        current_window = con->max_window_seq;
    }

    // Prepare and enqueue new packets from app_buf into the send window
    while (con->app_buf_size > 0 && con->send_buf_size < current_window) {
        int current_slot = con->next_seq % MAX_WINDOW_SIZE;

        int payload_len = con->app_buf_size;
        if (payload_len > MAX_DATA_SIZE) {
            payload_len = MAX_DATA_SIZE;
        }

        char send_buf[MAX_SEGMENT_SIZE];
        int buffer_used_size = 0;

        // Prepare data header
        struct poli_tcp_data_hdr *data_header = (struct poli_tcp_data_hdr *)malloc(sizeof(struct poli_tcp_data_hdr));
        data_header->protocol_id = POLI_PROTOCOL_ID;
        data_header->conn_id = con->conn_id;
        data_header->type = TYPE_DATA;
        data_header->seq_num = htons(con->next_seq);
        data_header->len = htons(payload_len);

        // Copy header then payload into local send buffer
        memcpy(send_buf, data_header, sizeof(struct poli_tcp_data_hdr));
        buffer_used_size += sizeof(struct poli_tcp_data_hdr);

        memcpy(send_buf + buffer_used_size, con->app_buf + con->app_buf_read_off, payload_len);
        buffer_used_size += payload_len;

        // Save the assembled segment into the window slot
        memcpy(con->send_buf[current_slot].data, send_buf, buffer_used_size);
        con->send_buf[current_slot].len = buffer_used_size;
        con->send_buf[current_slot].sent = 0;
        con->send_buf[current_slot].acked = 0;

        // Advance app_buf read cursor
        con->app_buf_read_off += payload_len;
        con->app_buf_size -= payload_len;
        if (con->app_buf_size == 0) con->app_buf_read_off = 0;

        con->next_seq = (con->next_seq + 1) % (MAX_WINDOW_SIZE * 2);
        con->send_buf_size++;

        free(data_header);
    }

    // Transmit any slots not yet sent
    uint16_t seq_iterator = con->send_base;
    for (int i = 0; i < con->send_buf_size; i++) {
        int slot = seq_iterator % MAX_WINDOW_SIZE;
        if (con->send_buf[slot].sent == 0) {
            transmit_packet(con, slot);
        }
        seq_iterator = (seq_iterator + 1) % (MAX_WINDOW_SIZE * 2);
    }
}

int send_data(int conn_id, char *buffer, int len)
{
    /* Write ALL len bytes before returning so the client doesn't pay the
     * 500ms penalty from the usleep in client.cpp on a partial return */
    int size = 0;

    while (size < len) {
        pthread_mutex_lock(&cons[conn_id]->con_lock);

        /* We will write code here as to not have sync problems with sender_handler */
        struct connection *con = cons[conn_id];

        int max_capacity = sizeof(con->app_buf);
        int write_offset = con->app_buf_read_off + con->app_buf_size;

        // Compact buffer if the write pointer would overflow the backing array
        if (write_offset + (len - size) > max_capacity && con->app_buf_size > 0) {
            memmove(con->app_buf, con->app_buf + con->app_buf_read_off, con->app_buf_size);
            con->app_buf_read_off = 0;
            write_offset = con->app_buf_size;
        }

        int available_space = max_capacity - con->app_buf_read_off - con->app_buf_size;

        if (available_space > 0) {
            int chunk_size = len - size;
            if (available_space < chunk_size) {
                chunk_size = available_space;
            }

            memcpy(con->app_buf + con->app_buf_read_off + con->app_buf_size, buffer + size, chunk_size);
            con->app_buf_size += chunk_size;
            size += chunk_size;

            // Kick the window immediately so we don't wait for a timer or ACK
            process_send_window(con);
        }

        pthread_mutex_unlock(&cons[conn_id]->con_lock);

        if (size < len) {
            usleep(500); // Wait for buffer space to free up
        }
    }

    return size;
}

void *sender_handler(void *arg)
{
    int res = 0;
    char buf[MAX_SEGMENT_SIZE];

    while (1) {

        if (cons.size() == 0) {
            continue;
        }

        int conn_id = -1;
        do {
            res = recv_message_or_timeout(buf, MAX_SEGMENT_SIZE, &conn_id);
        } while(res == -14);

        pthread_mutex_lock(&cons[conn_id]->con_lock);

        /* Handle segment received from the receiver. We use this between locks
        as to not have synchronization issues with the send_data calls which are
        on the main thread */
        struct connection *con = cons[conn_id];

        if (res == -1) {
            // Timeout expired => retransmit all in-flight packets
            if (con->send_buf_size > 0 || con->recv_window > 0) {
                uint16_t seq_iterator = con->send_base;
                for (int i = 0; i < con->send_buf_size; i++) {
                    con->send_buf[seq_iterator % MAX_WINDOW_SIZE].sent = 0;
                    seq_iterator = (seq_iterator + 1) % (MAX_WINDOW_SIZE * 2);
                }
                process_send_window(con);
            }
        } else {
            // Process incoming ACK
            struct poli_tcp_ctrl_hdr *ctrl_header = (struct poli_tcp_ctrl_hdr *)buf;

            if (ctrl_header->protocol_id == POLI_PROTOCOL_ID && ctrl_header->type == TYPE_ACK) {
                uint16_t received_ack = ntohs(ctrl_header->ack_num);
                uint16_t received_window = ntohs(ctrl_header->recv_window);

                con->recv_window = received_window;

                // Slide the send window forward up to received_ack
                while (con->send_buf_size > 0 && con->send_base != received_ack) {
                    con->send_buf[con->send_base % MAX_WINDOW_SIZE].acked = 1;
                    con->send_base = (con->send_base + 1) % (MAX_WINDOW_SIZE * 2);
                    con->send_buf_size--;
                }

                process_send_window(con);
            }
        }

        pthread_mutex_unlock(&cons[conn_id]->con_lock);
    }
}

int setup_connection(uint32_t ip, uint16_t port)
{
    /* Implement the sender part of the Three Way Handshake. Blocks
    until the connection is established */

    struct connection *con = (struct connection *)malloc(sizeof(struct connection));
    memset(con, 0, sizeof(struct connection));
    int conn_id = 0;
    con->conn_id = conn_id;
    con->max_window_seq = bdp_window_size;

    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Use a receive timeout so we can retransmit the SYN if SYN-ACK is dropped */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error");
    }

    /* We send the SYN to port 8032. We receive a SYN-ACK carrying the data port
     * in its payload. We update servaddr with that port for all subsequent data. */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = ip;
    server_addr.sin_port = port;

    char send_buf[MAX_SEGMENT_SIZE];
    int buffer_used_size = 0;

    // Prepare SYN header
    struct poli_tcp_ctrl_hdr *syn_header = (struct poli_tcp_ctrl_hdr *)malloc(sizeof(struct poli_tcp_ctrl_hdr));
    syn_header->protocol_id = POLI_PROTOCOL_ID;
    syn_header->conn_id = conn_id;
    syn_header->type = TYPE_SYN;
    syn_header->ack_num = 0;
    syn_header->recv_window = 0;

    memcpy(send_buf, syn_header, sizeof(struct poli_tcp_ctrl_hdr));
    buffer_used_size += sizeof(struct poli_tcp_ctrl_hdr);

    char recv_buf[MAX_SEGMENT_SIZE];
    struct sockaddr_in from_addr;
    socklen_t addr_len = sizeof(from_addr);
    struct poli_tcp_ctrl_hdr *synack_header;
    int bytes_received;

    // Retransmit SYN until we receive a valid SYN-ACK with data port payload
    do {
        sendto(con->sockfd, send_buf, buffer_used_size, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        bytes_received = recvfrom(con->sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr, &addr_len);
        synack_header = (struct poli_tcp_ctrl_hdr *)recv_buf;
    } while (bytes_received < (int)(sizeof(struct poli_tcp_ctrl_hdr) + sizeof(uint16_t)) || synack_header->protocol_id != POLI_PROTOCOL_ID || synack_header->type != TYPE_SYN_ACK);

    // Disable receive timeout now that handshake is progressing
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Extract the data port sent by the server in the SYN-ACK payload
    uint16_t data_port;
    memcpy(&data_port, recv_buf + sizeof(struct poli_tcp_ctrl_hdr), sizeof(uint16_t));
    con->servaddr = server_addr;
    con->servaddr.sin_port = data_port;

    con->recv_window = ntohs(synack_header->recv_window);
    con->send_base = 0;
    con->next_seq = 0;
    con->send_buf_size = 0;
    con->app_buf_size = 0;
    con->app_buf_read_off = 0;

    // Complete the three-way handshake with ACK
    struct poli_tcp_ctrl_hdr *ack_header = (struct poli_tcp_ctrl_hdr *)malloc(sizeof(struct poli_tcp_ctrl_hdr));
    ack_header->protocol_id = POLI_PROTOCOL_ID;
    ack_header->conn_id = conn_id;
    ack_header->type = TYPE_ACK;
    ack_header->ack_num = 0;
    ack_header->recv_window = 0;

    sendto(con->sockfd, ack_header, sizeof(struct poli_tcp_ctrl_hdr), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

    /* Since we can have multiple connections, we want to know if data is available
       on the socket used by a given connection. We use POLL for this */
    data_fds[fdmax].fd = con->sockfd;
    data_fds[fdmax].events = POLLIN;

    /* This creates a timer and sets it to trigger periodically. We use this
       to know if a timeout has happened on our connection */
    timer_fds[fdmax].fd = timerfd_create(CLOCK_REALTIME, 0);
    timer_fds[fdmax].events = POLLIN;
    struct itimerspec spec;
    long timeout_ns = (long)timeout_interval_ms * 1000000L;
    spec.it_value.tv_sec = timeout_ns / 1000000000L;
    spec.it_value.tv_nsec = timeout_ns % 1000000000L;
    spec.it_interval.tv_sec = timeout_ns / 1000000000L;
    spec.it_interval.tv_nsec = timeout_ns % 1000000000L;
    timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);
    fdmax++;

    pthread_mutex_init(&con->con_lock, NULL);
    cons.insert({conn_id, con});

    DEBUG_PRINT("Connection established!\n");

    free(syn_header);
    free(ack_header);
    return conn_id;
}

void init_sender(int speed, int delay)
{
    pthread_t thread1;
    int ret;

    // Calculate BDP window: segments in flight = bandwidth * RTT / segment_size
    int bdp = (int)((speed * 1000000.0 / 8.0) * (2.0 * delay / 1000.0) / MAX_DATA_SIZE);
    if (bdp < 4) bdp = 4;
    if (bdp > MAX_WINDOW_SIZE) bdp = MAX_WINDOW_SIZE;
    bdp_window_size = bdp;

    // Use 2*RTT as retransmit timeout
    timeout_interval_ms = 4 * delay;
    if (timeout_interval_ms < 5) timeout_interval_ms = 5;

    /* Create the sender handler thread */
    ret = pthread_create(&thread1, NULL, sender_handler, NULL);
    assert(ret == 0);
}
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

static int listen_sockfd = -1;
static int global_recv_buf_capacity = 0;
static int next_conn_id = 0;

// Helper to send a cumulative ACK back to the sender
void send_ack(struct connection *con) {
    char buf[sizeof(struct poli_tcp_ctrl_hdr)];
    int buffer_used_size = 0;

    struct poli_tcp_ctrl_hdr *ack_header = (struct poli_tcp_ctrl_hdr *)malloc(sizeof(struct poli_tcp_ctrl_hdr));
    ack_header->protocol_id = POLI_PROTOCOL_ID;
    ack_header->conn_id = con->conn_id;
    ack_header->type = TYPE_ACK;
    ack_header->ack_num = htons(con->last_ack_sent);
    // Advertise remaining space in segments (flow control)
    ack_header->recv_window = htons((con->recv_buf_capacity - con->recv_buf_size) / MAX_DATA_SIZE);

    memcpy(buf, ack_header, sizeof(struct poli_tcp_ctrl_hdr));
    buffer_used_size += sizeof(struct poli_tcp_ctrl_hdr);

    sendto(con->sockfd, buf, buffer_used_size, 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

    free(ack_header);
}

void set_reply_port(int conn_id, uint16_t port)
{
    pthread_mutex_lock(&cons[conn_id]->con_lock);
    cons[conn_id]->reply_port = port;
    pthread_mutex_unlock(&cons[conn_id]->con_lock);
}

int send_response(int conn_id, char *buffer, int len)
{
    struct connection *con = cons[conn_id];
    int ret = -1;

    pthread_mutex_lock(&con->con_lock);

    if (con->reply_port != 0) {
        struct sockaddr_in reply_addr = con->servaddr;
        reply_addr.sin_port = htons(con->reply_port);
        ret = sendto(con->sockfd, buffer, len, 0, (struct sockaddr *)&reply_addr, sizeof(reply_addr));
    }

    pthread_mutex_unlock(&con->con_lock);
    return ret;
}

int recv_data(int conn_id, char *buffer, int len)
{
    int size = 0;

    pthread_mutex_lock(&cons[conn_id]->con_lock);

    // Block until there is data available in the receive buffer
    while (cons[conn_id]->recv_buf_size == 0) {
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
        usleep(1000);
        pthread_mutex_lock(&cons[conn_id]->con_lock);
    }

    struct connection *con = cons[conn_id];

    size = len;
    if (con->recv_buf_size < size) {
        size = con->recv_buf_size;
    }

    memcpy(buffer, con->recv_buf + con->recv_buf_read_off, size);

    con->recv_buf_read_off += size;
    con->recv_buf_size -= size;

    // Reset read offset when buffer is fully drained
    if (con->recv_buf_size == 0) {
        con->recv_buf_read_off = 0;
    }

    pthread_mutex_unlock(&cons[conn_id]->con_lock);

    return size;
}

void *receiver_handler(void *arg)
{
    char segment[MAX_SEGMENT_SIZE];
    int res;
    DEBUG_PRINT("Starting receiver handler\n");

    while (1) {

        int conn_id = -1;
        do {
            res = recv_message_or_timeout(segment, MAX_SEGMENT_SIZE, &conn_id);
        } while(res == -14);

        pthread_mutex_lock(&cons[conn_id]->con_lock);

        /* Handle segment received or timeout. We use this between locks
        as to not have synchronization issues with the recv_data calls which are
        on the main thread */
        struct connection *con = cons[conn_id];

        if (res == -1) {
            // Timer expired => resend last ACK to unblock sender (breaks zero-window deadlock)
            send_ack(con);
            pthread_mutex_unlock(&con->con_lock);
            continue;
        }

        // Process incoming data segment
        struct poli_tcp_data_hdr *data_header = (struct poli_tcp_data_hdr *)segment;

        if (data_header->protocol_id != POLI_PROTOCOL_ID || data_header->type != TYPE_DATA) {
            pthread_mutex_unlock(&con->con_lock);
            continue;
        }

        uint16_t seq_num = ntohs(data_header->seq_num);
        uint16_t data_len = ntohs(data_header->len);
        char *payload = segment + sizeof(struct poli_tcp_data_hdr);

        if (seq_num == con->expected_seq) {
            int free_space = con->recv_buf_capacity - con->recv_buf_size;
            int write_offset = con->recv_buf_read_off + con->recv_buf_size;

            if ((int)data_len <= free_space) {
                // Compact buffer if the write pointer would overflow the backing array
                if (write_offset + (int)data_len > (int)sizeof(con->recv_buf)) {
                    memmove(con->recv_buf, con->recv_buf + con->recv_buf_read_off, con->recv_buf_size);
                    con->recv_buf_read_off = 0;
                    write_offset = con->recv_buf_size;
                }

                memcpy(con->recv_buf + write_offset, payload, data_len);
                con->recv_buf_size += data_len;

                con->expected_seq = (con->expected_seq + 1) % (MAX_WINDOW_SIZE * 2);
                con->last_ack_sent = con->expected_seq;
            }
            // No room => drop segment, sender will retransmit on timeout
        }
        // Out-of-order or duplicate => re-ACK the last accepted sequence

        send_ack(con);

        pthread_mutex_unlock(&con->con_lock);
    }
}

int wait4connect(uint32_t ip, uint16_t port)
{
    (void)ip;
    (void)port;

    /* Wait for a client SYN, perform three-way handshake, and return a connection id */

    struct connection *con = (struct connection *)malloc(sizeof(struct connection));
    memset(con, 0, sizeof(struct connection));

    int conn_id = next_conn_id++;

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buf[MAX_SEGMENT_SIZE];
    struct poli_tcp_ctrl_hdr *syn_header;
    int bytes_received;

    // Wait for a valid SYN on the listen socket
    do {
        bytes_received = recvfrom(listen_sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &addr_len);
        syn_header = (struct poli_tcp_ctrl_hdr *)buf;
    } while (bytes_received < (int)sizeof(struct poli_tcp_ctrl_hdr) || syn_header->protocol_id != POLI_PROTOCOL_ID || syn_header->type != TYPE_SYN);

    // Create a per-client socket and bind it to a random OS-chosen port
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in data_addr;
    memset(&data_addr, 0, sizeof(data_addr));
    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = INADDR_ANY;
    data_addr.sin_port = 0;
    ::bind(con->sockfd, (struct sockaddr *)&data_addr, sizeof(data_addr));

    // Retrieve the port the OS assigned
    socklen_t slen = sizeof(data_addr);
    getsockname(con->sockfd, (struct sockaddr *)&data_addr, &slen);
    uint16_t data_port = data_addr.sin_port;

    con->conn_id = conn_id;
    con->servaddr = client_addr;
    con->recv_buf_capacity = global_recv_buf_capacity;
    con->expected_seq = 0;
    con->last_ack_sent = 0;
    con->recv_buf_size = 0;
    con->recv_buf_read_off = 0;

    pthread_mutex_init(&con->con_lock, NULL);
    cons.insert({conn_id, con});

    // Build SYN-ACK with the data port in its payload
    char synack_buf[sizeof(struct poli_tcp_ctrl_hdr) + sizeof(uint16_t)];
    int synack_buf_size = 0;

    struct poli_tcp_ctrl_hdr *synack_header = (struct poli_tcp_ctrl_hdr *)malloc(sizeof(struct poli_tcp_ctrl_hdr));
    synack_header->protocol_id = POLI_PROTOCOL_ID;
    synack_header->conn_id = conn_id;
    synack_header->type = TYPE_SYN_ACK;
    synack_header->ack_num = htons(0);
    synack_header->recv_window = htons(con->recv_buf_capacity / MAX_DATA_SIZE);

    memcpy(synack_buf, synack_header, sizeof(struct poli_tcp_ctrl_hdr));
    synack_buf_size += sizeof(struct poli_tcp_ctrl_hdr);

    // Append the data port so the client knows where to send data
    memcpy(synack_buf + synack_buf_size, &data_port, sizeof(uint16_t));
    synack_buf_size += sizeof(uint16_t);

    /* Use a receive timeout so we retransmit SYN-ACK if the ACK is dropped */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error");
    }

    struct poli_tcp_ctrl_hdr *ack_header;
    int ack_received;

    // Retransmit SYN-ACK until we get the final ACK (or the client starts sending data)
    do {
        sendto(listen_sockfd, synack_buf, synack_buf_size, 0, (struct sockaddr *)&client_addr, addr_len);

        // Wait for ACK on the per-connection socket so receiver_handler cannot steal it
        ack_received = recvfrom(con->sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &addr_len);
        ack_header = (struct poli_tcp_ctrl_hdr *)buf;

        // If the client already started sending data, treat it as an implicit ACK
        if (ack_received >= (int)sizeof(struct poli_tcp_data_hdr)) {
            struct poli_tcp_data_hdr *data_hdr = (struct poli_tcp_data_hdr *)buf;
            if (data_hdr->protocol_id == POLI_PROTOCOL_ID && data_hdr->type == TYPE_DATA) {
                break;
            }
        }
    } while (ack_received < (int)sizeof(struct poli_tcp_ctrl_hdr) || ack_header->protocol_id != POLI_PROTOCOL_ID || ack_header->type != TYPE_ACK);

    // Disable receive timeout now that handshake is complete
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Register with poll only after handshake is fully complete so
       receiver_handler cannot race with the ACK recvfrom above */
    data_fds[fdmax].fd = con->sockfd;
    data_fds[fdmax].events = POLLIN;

    /* Per-connection periodic ACK timer to break zero-window deadlocks.
       5ms matches the sender retransmit timeout for a 2ms-delay link */
    timer_fds[fdmax].fd = timerfd_create(CLOCK_REALTIME, 0);
    timer_fds[fdmax].events = POLLIN;
    struct itimerspec spec;
    spec.it_value.tv_sec = 0;
    spec.it_value.tv_nsec = 5 * 1000000L;
    spec.it_interval.tv_sec = 0;
    spec.it_interval.tv_nsec = 5 * 1000000L;
    timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);
    fdmax++;

    DEBUG_PRINT("Connection established!\n");

    free(synack_header);
    return conn_id;
}

void init_receiver(int recv_buffer_bytes)
{
    pthread_t thread1;
    int ret;

    /* The backing array is fixed, so never advertise more than it can hold */
    if (recv_buffer_bytes <= 0 || recv_buffer_bytes > MAX_DATA_SIZE * RECV_BUF_SEGMENTS) {
        recv_buffer_bytes = MAX_DATA_SIZE * RECV_BUF_SEGMENTS;
    }

    global_recv_buf_capacity = recv_buffer_bytes;

    // Create the listen socket and bind it to port 8032
    listen_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8032);
    ::bind(listen_sockfd, (struct sockaddr *)&addr, sizeof(addr));

    /* Create the receiver handler thread */
    ret = pthread_create(&thread1, NULL, receiver_handler, NULL);
    assert(ret == 0);
}
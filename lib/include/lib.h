#pragma once
#include <cstdint>
#include "utils.h"
#include "protocol.h"
#include <arpa/inet.h>
#include <pthread.h>
 
/* Maximum segment size, change as you see fit */
#define MAX_DATA_SIZE 512
#define MAX_SEGMENT_SIZE (MAX_DATA_SIZE + sizeof(struct poli_tcp_data_hdr))
 
#define MAX_CONNECTIONS 32
 
/* Packet type values */
#define TYPE_SYN 1
#define TYPE_SYN_ACK 2
#define TYPE_ACK 3
#define TYPE_DATA 4
 
/* Window sizing */
#define MAX_WINDOW_SIZE 64
#define RECV_BUF_SEGMENTS 128
 
struct send_slot {
    char data[MAX_DATA_SIZE + 32];
    int len;
    int sent;
    int acked;
};

/* Protocol control block. Tracks the parameters of a connection. 
 * Extend it with other parameters such as last_ack or status if the protocol
 * needs them. */
struct connection {
    /* common window for both the sender and receiver. */
    /* list window: A window representation */
    int sockfd; /* socket used for this connection */
    int conn_id; /* connection identifier */
    struct sockaddr_in servaddr; /* used to identify the destination */
    pthread_mutex_t con_lock; /* Used for syncronization with the handler thread and read/send calls.*/

    int max_window_seq; /* max in-flight segments (BDP-derived) */
    int recv_window; /* last advertised recv window from peer */
 
    struct send_slot send_buf[MAX_WINDOW_SIZE];
    uint16_t send_base; /* seq num of oldest unacked segment */
    uint16_t next_seq; /* seq num to assign to next new segment */
    int send_buf_size; /* number of slots currently in the window */
 
    char app_buf[MAX_DATA_SIZE * MAX_WINDOW_SIZE];
    int app_buf_size;
    int app_buf_read_off;  /* read cursor into app_buf */
 
    /* --- receiver fields --- */
    char recv_buf[MAX_DATA_SIZE * RECV_BUF_SEGMENTS];
    int recv_buf_size; /* bytes currently held */
    int recv_buf_read_off; /* read cursor into recv_buf */
    int recv_buf_capacity; /* max bytes (from init_receiver arg) */
    uint16_t expected_seq; /* next seq num expected from sender */
    uint16_t last_ack_sent; /* last ack_num sent to sender */

    /* --- reply channel (server side) --- */
    uint16_t reply_port; /* client UDP port for command responses */
};

/* ########## API that we expose to the application ########### */

/* Equivalent of listen. Ran by the server to waits for a connection from a
 * client. Returns a connection id. Blocking untill it receives a connection
 * request */
int wait4connect(uint32_t ip, uint16_t port);
/* Equivalent of connect. Used by the client to connect to a server. */
int setup_connection(uint32_t ip, uint16_t port);
/* Equivalent to recv. Blocking if there is no data to be written in buffer */
int recv_data(int connectionid, char *buffer, int len);
/* Equivalent to send. Used by the client to send a stream of bytes as segments */
int send_data(int conn_id, char *buffer, int len);
/* Server-side reply over a separate client UDP socket. Returns bytes sent or
 * -1 if the client has not registered a reply port. */
int send_response(int conn_id, char *buffer, int len);
/* Register the UDP port where a client listens for command responses. */
void set_reply_port(int conn_id, uint16_t port);
/* Used to initialize your protocol on the receiver side. */
void init_receiver(int recv_buffer_bytes);
/* Used to initialize your protocol on the sender side */
void init_sender(int speed, int delay);

/* ######### Internal API used by sender and receiver ########### */
int recv_message_or_timeout(char *buff, size_t len, int *conn_id);
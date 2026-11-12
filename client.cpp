#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include "lib.h"
#include "crypto.h"

using namespace std;

#define DEFAULT_PORT 8032
#define DEFAULT_SPEED 10
#define DEFAULT_DELAY 2
#define MAX_COMMAND_LINE 1024
#define MAX_REPLY_SIZE 8192
#define REPLY_TIMEOUT_SEC 2
#define FLUSH_DELAY_US 500000

int main(int argc, char *argv[])
{
    const char *host = "127.0.0.1";
    int port = DEFAULT_PORT;
    int speed = DEFAULT_SPEED;
    int delay = DEFAULT_DELAY;

    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
    }
    if (argc > 3) {
        speed = atoi(argv[3]);
    }
    if (argc > 4) {
        delay = atoi(argv[4]);
    }

    /* Responses arrive on a separate UDP socket so they never compete with the
     * sender handler, which owns the protocol socket and its ACK processing. */
    int reply_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in reply_addr;
    memset(&reply_addr, 0, sizeof(reply_addr));
    reply_addr.sin_family = AF_INET;
    reply_addr.sin_addr.s_addr = INADDR_ANY;
    reply_addr.sin_port = 0;
    ::bind(reply_sockfd, (struct sockaddr *)&reply_addr, sizeof(reply_addr));

    socklen_t reply_addr_len = sizeof(reply_addr);
    getsockname(reply_sockfd, (struct sockaddr *)&reply_addr, &reply_addr_len);
    uint16_t reply_port = ntohs(reply_addr.sin_port);

    struct timeval tv;
    tv.tv_sec = REPLY_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(reply_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    init_sender(speed, delay);

    /* Resolve names too, so the client can use Docker service names such as
     * "server" in addition to numeric addresses. */
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int ret = getaddrinfo(host, NULL, &hints, &result);
    if (ret != 0 || result == NULL) {
        fprintf(stderr, "Invalid address: %s\n", host);
        return 1;
    }

    uint32_t ip = ((struct sockaddr_in *)result->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(result);

    int conn_id = setup_connection(ip, htons((uint16_t)port));
    fprintf(stderr, "Connected to %s:%d (connection %d)\n", host, port, conn_id);

    /* Each connection gets a fresh X25519 key pair */
    struct crypto_keys keys;
    memset(&keys, 0, sizeof(keys));
    if (crypto_keypair(&keys) != 0) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    /* Tell the server where to send command responses */
    char register_cmd[64];
    int register_len = snprintf(register_cmd, sizeof(register_cmd), "REGISTER %u\n",
                                (unsigned int)reply_port);
    if (register_len > 0) {
        send_data(conn_id, register_cmd, register_len);
    }

    /* Send our public key, then wait for the server's public key on the reply
     * socket. Both sides derive the same two AES-256-GCM keys. */
    char public_hex[CRYPTO_KEY_SIZE * 2 + 1];
    char key_cmd[128];
    crypto_hex_encode(keys.public_key, CRYPTO_KEY_SIZE, public_hex);
    int key_len = snprintf(key_cmd, sizeof(key_cmd), "KEY %s\n", public_hex);
    if (key_len > 0) {
        send_data(conn_id, key_cmd, key_len);
    }

    uint8_t server_public[CRYPTO_KEY_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    int key_size = recvfrom(reply_sockfd, server_public, sizeof(server_public), 0,
                            (struct sockaddr *)&from_addr, &from_len);
    DEBUG_PRINT("key exchange: received %d bytes\n", key_size);

    if (key_size != CRYPTO_KEY_SIZE || crypto_shared(&keys, server_public) != 0) {
        fprintf(stderr, "Key exchange failed\n");
        crypto_free(&keys);
        return 1;
    }
    fprintf(stderr, "Encrypted channel established\n");

    char line[MAX_COMMAND_LINE + 2];
    char frame[CRYPTO_MAX_FRAME];
    char reply_frame[CRYPTO_MAX_FRAME];
    char plain[MAX_REPLY_SIZE + 1];
    int interactive = isatty(STDIN_FILENO);

    while (1) {
        if (interactive) {
            fprintf(stderr, "db> ");
        }

        if (fgets(line, MAX_COMMAND_LINE, stdin) == NULL) {
            break;
        }

        int line_len = (int)strlen(line);
        while (line_len > 0 && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r')) {
            line[--line_len] = '\0';
        }

        /* Blank input is not a command; the server would not answer it */
        char *first = line;
        while (*first == ' ' || *first == '\t') {
            first++;
        }
        if (*first == '\0') {
            continue;
        }

        int frame_len = crypto_encrypt(keys.c2s_key, line, line_len, frame, sizeof(frame));
        if (frame_len <= 0) {
            fprintf(stderr, "Encryption failed\n");
            continue;
        }
        send_data(conn_id, frame, frame_len);

        struct sockaddr_in reply_from;
        socklen_t reply_from_len = sizeof(reply_from);
        int reply_size = recvfrom(reply_sockfd, reply_frame, sizeof(reply_frame), 0,
                                  (struct sockaddr *)&reply_from, &reply_from_len);

        if (reply_size < 0) {
            fprintf(stderr, "Response timeout\n");
            continue;
        }

        int plain_len = crypto_decrypt(keys.s2c_key, reply_frame, reply_size,
                                       plain, sizeof(plain));
        if (plain_len < 0) {
            fprintf(stderr, "Decryption failed\n");
            continue;
        }

        (void)fwrite(plain, 1, plain_len, stdout);
        (void)fflush(stdout);
    }

    crypto_free(&keys);

    /* Give the sender handler time to transmit the last command */
    usleep(FLUSH_DELAY_US);
    return 0;
}

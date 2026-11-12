#include <pthread.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cassert>
#include <string>
#include <map>
#include <unistd.h>
#include "lib.h"
#include "crypto.h"

using namespace std;

#define MAX_COMMAND_LINE 1024
#define MAX_RESPONSE_SIZE 8192

/* Small in-RAM key-value store shared by every connection. The lock is held
 * only while touching the map, never while sending a response. */
static std::map<std::string, std::string> db;
static pthread_mutex_t db_lock = PTHREAD_MUTEX_INITIALIZER;

/* Per-connection application state. One reader thread owns one of these and
 * keeps the key material for that client. */
struct conn_state {
    int conn_id;
    int encrypted;
    struct crypto_keys keys;
    char line[MAX_COMMAND_LINE];
    int line_len;
    char frame_buf[CRYPTO_MAX_FRAME * 2];
    int frame_len;
};

/* Trim leading and trailing spaces, tabs, carriage returns and newlines. */
static char *trim(char *text)
{
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
        text++;
    }

    int len = (int)strlen(text);
    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t' ||
                       text[len - 1] == '\r' || text[len - 1] == '\n')) {
        text[--len] = '\0';
    }

    return text;
}

/* Encrypt one response line and send it to the client's registered reply port. */
static void reply(struct conn_state *state, const std::string &text)
{
    std::string out = text + "\n";
    char frame[CRYPTO_MAX_FRAME];
    int frame_len;

    if (!state->encrypted) {
        return;
    }

    if (out.size() > (size_t)MAX_RESPONSE_SIZE) {
        out.resize(MAX_RESPONSE_SIZE);
    }

    frame_len = crypto_encrypt(state->keys.s2c_key, (char *)out.c_str(), (int)out.size(),
                               frame, sizeof(frame));
    if (frame_len > 0) {
        send_response(state->conn_id, frame, frame_len);
    }
}

static void handle_set(struct conn_state *state, char *args)
{
    char *key = trim(args);
    char *value = key;

    while (*value != ' ' && *value != '\t' && *value != '\0') {
        value++;
    }

    if (*key == '\0' || *value == '\0') {
        reply(state, "ERROR usage: set <key> <value>");
        return;
    }

    *value = '\0';
    value++;
    value = trim(value);

    pthread_mutex_lock(&db_lock);
    db[key] = value;
    pthread_mutex_unlock(&db_lock);

    reply(state, "OK");
}

static void handle_get(struct conn_state *state, char *args)
{
    char *key = trim(args);
    std::string response;

    if (*key == '\0') {
        reply(state, "ERROR usage: get <key>");
        return;
    }

    pthread_mutex_lock(&db_lock);
    auto it = db.find(key);
    if (it == db.end()) {
        response = "(nil)";
    } else {
        response = it->second;
    }
    pthread_mutex_unlock(&db_lock);

    reply(state, response);
}

static void handle_delete(struct conn_state *state, char *args)
{
    char *key = trim(args);
    std::string response = "(nil)";

    if (*key == '\0') {
        reply(state, "ERROR usage: delete <key>");
        return;
    }

    pthread_mutex_lock(&db_lock);
    auto it = db.find(key);
    if (it != db.end()) {
        db.erase(it);
        response = "OK";
    }
    pthread_mutex_unlock(&db_lock);

    reply(state, response);
}

static void handle_print(struct conn_state *state)
{
    std::string response;
    char frame[CRYPTO_MAX_FRAME];
    int frame_len;

    pthread_mutex_lock(&db_lock);
    for (auto const& entry : db) {
        response += entry.first + " = " + entry.second + "\n";
    }
    pthread_mutex_unlock(&db_lock);

    if (response.empty()) {
        response = "(empty)\n";
    }

    if (response.size() > (size_t)MAX_RESPONSE_SIZE) {
        response.resize(MAX_RESPONSE_SIZE);
    }

    if (!state->encrypted) {
        return;
    }

    frame_len = crypto_encrypt(state->keys.s2c_key, (char *)response.c_str(), (int)response.size(),
                               frame, sizeof(frame));
    if (frame_len > 0) {
        send_response(state->conn_id, frame, frame_len);
    }
}

/* Plaintext control lines are only accepted before the key exchange. They
 * carry the reply port and the client's X25519 public key. */
static void process_control_line(struct conn_state *state, char *line)
{
    line = trim(line);
    if (*line == '\0') {
        return;
    }

    DEBUG_PRINT("conn %d control: %s\n", state->conn_id, line);

    if (strncmp(line, "REGISTER ", 9) == 0) {
        int port = atoi(line + 9);
        if (port > 0 && port <= 65535) {
            set_reply_port(state->conn_id, (uint16_t)port);
        }
        return;
    }

    if (strncmp(line, "KEY ", 4) == 0) {
        uint8_t peer_public[CRYPTO_KEY_SIZE];
        int decoded = crypto_hex_decode(line + 4, peer_public, CRYPTO_KEY_SIZE);
        int shared = -1;

        if (decoded == CRYPTO_KEY_SIZE) {
            shared = crypto_shared(&state->keys, peer_public);
        }

        DEBUG_PRINT("conn %d: key decode=%d shared=%d\n", state->conn_id, decoded, shared);

        if (decoded == CRYPTO_KEY_SIZE && shared == 0) {
            state->encrypted = 1;
            send_response(state->conn_id, (char *)state->keys.public_key, CRYPTO_KEY_SIZE);
            DEBUG_PRINT("conn %d: key exchange complete\n", state->conn_id);
        }
    }
}

static void process_command(struct conn_state *state, char *line)
{
    line = trim(line);
    if (*line == '\0') {
        return;
    }

    DEBUG_PRINT("conn %d: %s\n", state->conn_id, line);

    char *args = line;
    while (*args != ' ' && *args != '\t' && *args != '\0') {
        args++;
    }

    if (*args != '\0') {
        *args = '\0';
        args++;
    } else {
        args = NULL;
    }

    if (strcmp(line, "set") == 0) {
        if (args == NULL) {
            reply(state, "ERROR usage: set <key> <value>");
        } else {
            handle_set(state, args);
        }
    } else if (strcmp(line, "get") == 0) {
        if (args == NULL) {
            reply(state, "ERROR usage: get <key>");
        } else {
            handle_get(state, args);
        }
    } else if (strcmp(line, "delete") == 0) {
        if (args == NULL) {
            reply(state, "ERROR usage: delete <key>");
        } else {
            handle_delete(state, args);
        }
    } else if (strcmp(line, "print") == 0) {
        handle_print(state);
    } else {
        reply(state, "ERROR unknown command");
    }
}

static void process_plaintext(struct conn_state *state, char *buf, int size)
{
    for (int i = 0; i < size; i++) {
        if (buf[i] == '\n') {
            state->line[state->line_len] = '\0';
            process_control_line(state, state->line);
            state->line_len = 0;
        } else if (state->line_len < MAX_COMMAND_LINE - 1) {
            state->line[state->line_len++] = buf[i];
        }
    }
}

/* Rebuild encrypted frames from the byte stream. send_data may split a frame
 * across segments, so partial bytes stay in frame_buf between reads. */
static void process_frames(struct conn_state *state, char *buf, int size)
{
    if (state->frame_len + size > (int)sizeof(state->frame_buf)) {
        state->frame_len = 0;
        return;
    }

    memcpy(state->frame_buf + state->frame_len, buf, size);
    state->frame_len += size;

    while (state->frame_len >= 2) {
        uint16_t payload_len;
        int total;
        char plain[CRYPTO_MAX_PLAIN + 1];
        int plain_len;

        memcpy(&payload_len, state->frame_buf, 2);
        payload_len = ntohs(payload_len);
        total = (int)payload_len + 2;

        if (payload_len < CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE ||
            total > (int)sizeof(state->frame_buf)) {
            state->frame_len = 0;
            return;
        }

        if (state->frame_len < total) {
            break;
        }

        plain_len = crypto_decrypt(state->keys.c2s_key, state->frame_buf, total,
                                   plain, sizeof(plain));
        if (plain_len > 0) {
            plain[plain_len] = '\0';
            process_command(state, plain);
        } else if (plain_len < 0) {
            DEBUG_PRINT("conn %d: rejected encrypted frame\n", state->conn_id);
        }

        memmove(state->frame_buf, state->frame_buf + total, state->frame_len - total);
        state->frame_len -= total;
    }
}

static void *reader_handler(void *arg)
{
    struct conn_state *state = (struct conn_state *)arg;
    char buf[4096];

    while (1) {
        int size = recv_data(state->conn_id, buf, sizeof(buf));
        if (size <= 0) {
            break;
        }

        if (state->encrypted) {
            process_frames(state, buf, size);
        } else {
            process_plaintext(state, buf, size);
        }
    }

    crypto_free(&state->keys);
    free(state);
    return NULL;
}

int main(int argc, char *argv[])
{
    int recv_buffer_bytes = MAX_DATA_SIZE * RECV_BUF_SEGMENTS;

    if (argc > 1) {
        recv_buffer_bytes = atoi(argv[1]);
    }

    init_receiver(recv_buffer_bytes);
    fprintf(stderr, "Listening on UDP port 8032\n");
    fprintf(stderr, "Commands: set <key> <value>, get <key>, delete <key>, print\n");

    while (1) {
        int conn_id = wait4connect(0, 0);
        fprintf(stderr, "Connection %d established\n", conn_id);

        struct conn_state *state = (struct conn_state *)malloc(sizeof(struct conn_state));
        memset(state, 0, sizeof(struct conn_state));
        state->conn_id = conn_id;

        if (crypto_keypair(&state->keys) != 0) {
            fprintf(stderr, "Key generation failed for connection %d\n", conn_id);
            free(state);
            continue;
        }

        pthread_t thread;
        int ret = pthread_create(&thread, NULL, reader_handler, state);
        assert(ret == 0);
        pthread_detach(thread);
    }

    return 0;
}

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include "crypto.h"

using namespace std;

/* Derive one 32-byte key from the X25519 secret with HKDF-SHA256. The info
 * string separates the two directions, so each side has its own write key. */
static int derive_key(unsigned char *secret, size_t secret_len, const char *info, uint8_t *out)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t out_len = CRYPTO_KEY_SIZE;
    int ret = -1;

    if (ctx == NULL) {
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, (unsigned char *)"poli_tcp", 8) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, (int)secret_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, (unsigned char *)info, (int)strlen(info)) <= 0 ||
        EVP_PKEY_derive(ctx, out, &out_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (out_len == CRYPTO_KEY_SIZE) {
        ret = 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int crypto_keypair(struct crypto_keys *keys)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    size_t public_len = CRYPTO_KEY_SIZE;

    if (ctx == NULL) {
        return -1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);

    if (EVP_PKEY_get_raw_public_key(pkey, keys->public_key, &public_len) <= 0 ||
        public_len != CRYPTO_KEY_SIZE) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    keys->pkey = (void *)pkey;
    return 0;
}

int crypto_shared(struct crypto_keys *keys, uint8_t *peer_public)
{
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public, CRYPTO_KEY_SIZE);
    EVP_PKEY_CTX *ctx;
    unsigned char secret[64];
    size_t secret_len = 0;
    int ret = -1;

    if (peer == NULL || keys->pkey == NULL) {
        EVP_PKEY_free(peer);
        return -1;
    }

    ctx = EVP_PKEY_CTX_new((EVP_PKEY *)keys->pkey, NULL);
    if (ctx == NULL) {
        EVP_PKEY_free(peer);
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
        EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0 ||
        secret_len > sizeof(secret) ||
        EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);

    if (derive_key(secret, secret_len, "client-to-server", keys->c2s_key) == 0 &&
        derive_key(secret, secret_len, "server-to-client", keys->s2c_key) == 0) {
        ret = 0;
    }

    memset(secret, 0, sizeof(secret));
    return ret;
}

int crypto_encrypt(uint8_t *key, char *plain, int plain_len, char *out, int out_cap)
{
    unsigned char nonce[CRYPTO_NONCE_SIZE];
    unsigned char *frame = (unsigned char *)out;
    EVP_CIPHER_CTX *ctx;
    uint16_t payload_len;
    uint16_t net_len;
    int len = 0;
    int total = 0;

    if (plain_len < 0 || plain_len + CRYPTO_FRAME_OVERHEAD > out_cap) {
        return -1;
    }

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        return -1;
    }

    payload_len = (uint16_t)(CRYPTO_NONCE_SIZE + plain_len + CRYPTO_TAG_SIZE);
    net_len = htons(payload_len);
    memcpy(frame, &net_len, 2);
    memcpy(frame + 2, nonce, CRYPTO_NONCE_SIZE);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CRYPTO_NONCE_SIZE, NULL) <= 0 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0 ||
        EVP_EncryptUpdate(ctx, frame + 2 + CRYPTO_NONCE_SIZE, &len,
                          (unsigned char *)plain, plain_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total = len;

    if (EVP_EncryptFinal_ex(ctx, frame + 2 + CRYPTO_NONCE_SIZE + total, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CRYPTO_TAG_SIZE,
                            frame + 2 + CRYPTO_NONCE_SIZE + total) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 2 + CRYPTO_NONCE_SIZE + total + CRYPTO_TAG_SIZE;
}

int crypto_decrypt(uint8_t *key, char *frame, int frame_len, char *out, int out_cap)
{
    unsigned char *buf = (unsigned char *)frame;
    EVP_CIPHER_CTX *ctx;
    uint16_t payload_len;
    int cipher_len;
    int len = 0;
    int total = 0;
    int ret;

    if (frame_len < CRYPTO_FRAME_OVERHEAD) {
        return -1;
    }

    memcpy(&payload_len, buf, 2);
    payload_len = ntohs(payload_len);

    if ((int)payload_len + 2 != frame_len) {
        return -1;
    }

    cipher_len = payload_len - CRYPTO_NONCE_SIZE - CRYPTO_TAG_SIZE;
    if (cipher_len < 0 || cipher_len + 1 > out_cap) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CRYPTO_NONCE_SIZE, NULL) <= 0 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, buf + 2) <= 0 ||
        EVP_DecryptUpdate(ctx, (unsigned char *)out, &len,
                          buf + 2 + CRYPTO_NONCE_SIZE, cipher_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CRYPTO_TAG_SIZE,
                            buf + 2 + CRYPTO_NONCE_SIZE + cipher_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)out + total, &len);
    total += len;
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        return -1;
    }

    if (total < out_cap) {
        out[total] = '\0';
    }

    return total;
}

void crypto_hex_encode(uint8_t *in, int len, char *out)
{
    static const char digits[] = "0123456789abcdef";

    for (int i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int crypto_hex_decode(char *in, uint8_t *out, int out_cap)
{
    int len = (int)strlen(in);

    if (len % 2 != 0 || len / 2 > out_cap) {
        return -1;
    }

    for (int i = 0; i < len / 2; i++) {
        int high = hex_value(in[i * 2]);
        int low = hex_value(in[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return -1;
        }
        out[i] = (uint8_t)((high << 4) | low);
    }

    return len / 2;
}

void crypto_free(struct crypto_keys *keys)
{
    if (keys->pkey != NULL) {
        EVP_PKEY_free((EVP_PKEY *)keys->pkey);
        keys->pkey = NULL;
    }

    memset(keys->c2s_key, 0, CRYPTO_KEY_SIZE);
    memset(keys->s2c_key, 0, CRYPTO_KEY_SIZE);
}

#pragma once

#include <cstdint>

/* X25519 public keys and derived symmetric keys are 32 bytes. An encrypted
 * frame is [uint16 payload_len][12-byte nonce][ciphertext][16-byte tag]. */
#define CRYPTO_KEY_SIZE 32
#define CRYPTO_NONCE_SIZE 12
#define CRYPTO_TAG_SIZE 16
#define CRYPTO_FRAME_OVERHEAD (2 + CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE)
#define CRYPTO_MAX_PLAIN 9216
#define CRYPTO_MAX_FRAME (CRYPTO_FRAME_OVERHEAD + CRYPTO_MAX_PLAIN)

struct crypto_keys {
    void *pkey; /* EVP_PKEY * for the local X25519 key pair */
    uint8_t public_key[CRYPTO_KEY_SIZE];
    uint8_t c2s_key[CRYPTO_KEY_SIZE];
    uint8_t s2c_key[CRYPTO_KEY_SIZE];
};

/* Generate a fresh X25519 key pair and fill public_key. */
int crypto_keypair(struct crypto_keys *keys);
/* Derive c2s_key and s2c_key from our private key and the peer public key. */
int crypto_shared(struct crypto_keys *keys, uint8_t *peer_public);
/* Encrypt one message into [uint16 len][nonce][ciphertext][tag]. Returns the
 * frame length, or -1 on failure. */
int crypto_encrypt(uint8_t *key, char *plain, int plain_len, char *out, int out_cap);
/* Decrypt one complete frame. Returns the plaintext length, or -1 if the frame
 * is malformed or the authentication tag does not match. */
int crypto_decrypt(uint8_t *key, char *frame, int frame_len, char *out, int out_cap);
/* Hex helpers used to carry the public key in a text control line. */
void crypto_hex_encode(uint8_t *in, int len, char *out);
int crypto_hex_decode(char *in, uint8_t *out, int out_cap);
/* Free the local key pair and wipe the symmetric keys. */
void crypto_free(struct crypto_keys *keys);

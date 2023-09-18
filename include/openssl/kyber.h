#ifndef OPENSSL_HEADER_KYBER_H
#define OPENSSL_HEADER_KYBER_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define KYBER512_PUBLIC_KEY_BYTES  800
#define KYBER512_CIPHERTEXT_BYTES  768
#define KYBER512_PRIVATE_KEY_BYTES 1632
#define KYBER768_PUBLIC_KEY_BYTES  1184
#define KYBER768_CIPHERTEXT_BYTES  1088
#define KYBER768_PRIVATE_KEY_BYTES 2400

struct KYBER512_private_key {
  uint8_t opaque[KYBER512_PRIVATE_KEY_BYTES];
};
struct KYBER768_private_key {
  uint8_t opaque[KYBER768_PRIVATE_KEY_BYTES];
};
struct KYBER512_public_key {
  uint8_t opaque[KYBER512_PUBLIC_KEY_BYTES];
};
struct KYBER768_public_key {
  uint8_t opaque[KYBER768_PUBLIC_KEY_BYTES];
};

// KYBER_GENERATE_KEY_BYTES is the number of bytes of entropy needed to
// generate a keypair.
#define KYBER_GENERATE_KEY_BYTES 64

// KYBER_ENCAP_BYTES is the number of bytes of entropy needed to encapsulate a
// session key.
#define KYBER_ENCAP_BYTES 32

// KYBER_KEY_BYTES is the number of bytes in a shared key.
#define KYBER_KEY_BYTES 32

// KYBER512_generate_key is a deterministic function that outputs a public and
// private key based on the given entropy.
OPENSSL_EXPORT void KYBER512_generate_key(
    struct KYBER512_public_key *out_pub, struct KYBER512_private_key *out_priv,
    const uint8_t input[KYBER_GENERATE_KEY_BYTES]);

// KYBER768_generate_key is a deterministic function that outputs a public and
// private key based on the given entropy.
OPENSSL_EXPORT void KYBER768_generate_key(
    struct KYBER768_public_key *out_pub, struct KYBER768_private_key *out_priv,
    const uint8_t input[KYBER_GENERATE_KEY_BYTES]);

// KYBER512_encap is a deterministic function the generates and encrypts a random
// session key from the given entropy, writing those values to |out_shared_key|
// and |out_ciphertext|, respectively.
OPENSSL_EXPORT void KYBER512_encap(uint8_t out_ciphertext[KYBER512_CIPHERTEXT_BYTES],
                              uint8_t out_shared_key[KYBER_KEY_BYTES],
                              const struct KYBER512_public_key *in_pub,
                              const uint8_t in[KYBER_ENCAP_BYTES]);

// KYBER768_encap is a deterministic function the generates and encrypts a random
// session key from the given entropy, writing those values to |out_shared_key|
// and |out_ciphertext|, respectively.
OPENSSL_EXPORT void KYBER768_encap(uint8_t out_ciphertext[KYBER768_CIPHERTEXT_BYTES],
                              uint8_t out_shared_key[KYBER_KEY_BYTES],
                              const struct KYBER768_public_key *in_pub,
                              const uint8_t in[KYBER_ENCAP_BYTES]);

// KYBER_decap decrypts a session key from |ciphertext_len| bytes of
// |ciphertext|. If the ciphertext is valid, the decrypted key is written to
// |out_shared_key|. Otherwise a key dervied from |ciphertext| and a secret key (kept
// in |in_priv|) is written. If the ciphertext is the wrong length then it will
// leak which was done via side-channels. Otherwise it should perform either
// action in constant-time.
OPENSSL_EXPORT void KYBER512_decap(uint8_t out_shared_key[KYBER_KEY_BYTES],
                              const struct KYBER512_private_key *in_priv,
                              const uint8_t *ciphertext, size_t ciphertext_len);

// KYBER_decap decrypts a session key from |ciphertext_len| bytes of
// |ciphertext|. If the ciphertext is valid, the decrypted key is written to
// |out_shared_key|. Otherwise a key dervied from |ciphertext| and a secret key (kept
// in |in_priv|) is written. If the ciphertext is the wrong length then it will
// leak which was done via side-channels. Otherwise it should perform either
// action in constant-time.
OPENSSL_EXPORT void KYBER768_decap(uint8_t out_shared_key[KYBER_KEY_BYTES],
                              const struct KYBER768_private_key *in_priv,
                              const uint8_t *ciphertext, size_t ciphertext_len);

// KYBER512_marshal_public_key serialises |in_pub| to |out|.
OPENSSL_EXPORT void KYBER512_marshal_public_key(
    uint8_t out[KYBER512_PUBLIC_KEY_BYTES], const struct KYBER512_public_key *in_pub);

// KYBER768_marshal_public_key serialises |in_pub| to |out|.
OPENSSL_EXPORT void KYBER768_marshal_public_key(
    uint8_t out[KYBER768_PUBLIC_KEY_BYTES], const struct KYBER768_public_key *in_pub);

// KYBER512_parse_public_key sets |*out| to the public-key encoded in |in|.
OPENSSL_EXPORT void KYBER512_parse_public_key(
    struct KYBER512_public_key *out, const uint8_t in[KYBER512_PUBLIC_KEY_BYTES]);

// KYBER768_parse_public_key sets |*out| to the public-key encoded in |in|.
OPENSSL_EXPORT void KYBER768_parse_public_key(
    struct KYBER768_public_key *out, const uint8_t in[KYBER768_PUBLIC_KEY_BYTES]);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_KYBER_H

#ifndef PACKING_H
#define PACKING_H

#include <stdbool.h>
#include <stdint.h>
#include "params.h"
#include "poly.h"

#define pack_pk_rho DILITHIUM_NAMESPACE(pack_pk_rho)
void pack_pk_rho(uint8_t pk[CRYPTO_PUBLICKEYBYTES], const uint8_t rho[SEEDBYTES]);

#define pack_pk_t1 DILITHIUM_NAMESPACE(pack_pk_t1)
void pack_pk_t1(uint8_t pk[CRYPTO_PUBLICKEYBYTES], const poly* t1_elem, unsigned int idx);

#define pack_sk_rho DILITHIUM_NAMESPACE(pack_sk_rho)
void pack_sk_rho(uint8_t sk[CRYPTO_SECRETKEYBYTES], const uint8_t rho[SEEDBYTES]);

#define pack_sk_key DILITHIUM_NAMESPACE(pack_sk_key)
void pack_sk_key(uint8_t sk[CRYPTO_SECRETKEYBYTES], const uint8_t key[SEEDBYTES]);

#define pack_sk_tr DILITHIUM_NAMESPACE(pack_sk_tr)
void pack_sk_tr(uint8_t sk[CRYPTO_SECRETKEYBYTES], const uint8_t tr[SEEDBYTES]);

#define pack_sk_s1 DILITHIUM_NAMESPACE(pack_sk_s1)
void pack_sk_s1(uint8_t sk[CRYPTO_SECRETKEYBYTES], const poly *s1_elem, unsigned int idx);

#define pack_sk_s2 DILITHIUM_NAMESPACE(pack_sk_s2)
void pack_sk_s2(uint8_t sk[CRYPTO_SECRETKEYBYTES], const poly *s2_elem, unsigned int idx);

#define pack_sk_t0 DILITHIUM_NAMESPACE(pack_sk_t0)
void pack_sk_t0(uint8_t sk[CRYPTO_SECRETKEYBYTES], const poly *t0_elem, unsigned int idx);

#define pack_sig_c DILITHIUM_NAMESPACE(pack_sig_c)
void pack_sig_c(uint8_t sig[CRYPTO_BYTES], const uint8_t c[SEEDBYTES]);

#define pack_sig_z DILITHIUM_NAMESPACE(pack_sig_z)
void pack_sig_z(uint8_t sig[CRYPTO_BYTES], const poly* z_elem, unsigned int idx);

#define pack_sig_h DILITHIUM_NAMESPACE(pack_sig_h)
struct pack_sig_h {
  uint8_t* hbuf; /* reference to h-buffer in signature */
  unsigned int k; /* amount of written hints */
  unsigned int polys_written; /* hint polynomials written */
};

#define pack_sig_h_init DILITHIUM_NAMESPACE(pack_sig_h_init)
void pack_sig_h_init(struct pack_sig_h* w, uint8_t* sig);

#define pack_sig_h_update DILITHIUM_NAMESPACE(pack_sig_h_update)
void pack_sig_h_update(struct pack_sig_h* w, const poly* h);

#define unpack_pk_rho DILITHIUM_NAMESPACE(unpack_pk_rho)
void unpack_pk_rho(uint8_t rho[SEEDBYTES], const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);

#define unpack_pk_t1 DILITHIUM_NAMESPACE(unpack_pk_t1)
void unpack_pk_t1(poly *t1_elem, unsigned int idx, const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);

#define unpack_sk_rho DILITHIUM_NAMESPACE(unpack_sk_rho)
void unpack_sk_rho(uint8_t rho[SEEDBYTES], const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

#define unpack_sk_key DILITHIUM_NAMESPACE(unpack_sk_key)
void unpack_sk_key(uint8_t key[SEEDBYTES], const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

#define unpack_sk_tr DILITHIUM_NAMESPACE(unpack_sk_tr)
void unpack_sk_tr(uint8_t tr[SEEDBYTES], const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

#define unpack_sk_s1 DILITHIUM_NAMESPACE(unpack_sk_s1)
void unpack_sk_s1(poly* s1_elem, unsigned int idx, const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

#define unpack_sk_s2 DILITHIUM_NAMESPACE(unpack_sk_s2)
void unpack_sk_s2(poly* s2_elem, unsigned int idx, const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

#define unpack_sk_t0 DILITHIUM_NAMESPACE(unpack_sk_t0)
void unpack_sk_t0(poly* t0_elem, unsigned int idx, const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

#define unpack_sig_c DILITHIUM_NAMESPACE(unpack_sig_c)
void unpack_sig_c(uint8_t c[SEEDBYTES], const uint8_t sig[CRYPTO_BYTES]);

#define unpack_sig_z DILITHIUM_NAMESPACE(unpack_sig_z)
void unpack_sig_z(poly *z_elem, unsigned int idx, const uint8_t sig[CRYPTO_BYTES]);

#define unpack_sig_h DILITHIUM_NAMESPACE(unpack_sig_h)
struct unpack_sig_h {
  const uint8_t* hbuf; /* reference to h-buffer in signature */
  unsigned int k; /* amount of hints that were read */
  unsigned int polys_read; /* number of hint polynomials read */
  bool finished; /* we have finished reading hints */
  bool error; /* an error occured; signature invalid */
};

#define unpack_sig_h_init DILITHIUM_NAMESPACE(unpack_sig_h_init)
void unpack_sig_h_init(struct unpack_sig_h *r, const uint8_t *sig);

#define unpack_sig_h_update DILITHIUM_NAMESPACE(unpack_sig_h_update)
int unpack_sig_h_update(struct unpack_sig_h *r, poly *h_elem);

#endif

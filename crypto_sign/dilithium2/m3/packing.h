#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define pack_pk DILITHIUM_NAMESPACE(pack_pk)
void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES], const uint8_t rho[SEEDBYTES], const polyveck *t1);

#define pack_sk DILITHIUM_NAMESPACE(pack_sk)
void pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[SEEDBYTES],
             const uint8_t tr[SEEDBYTES],
             const uint8_t key[SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);

#define pack_sig_c DILITHIUM_NAMESPACE(pack_sig_c)
void pack_sig_c(uint8_t sig[CRYPTO_BYTES], const uint8_t c[SEEDBYTES]);

#define pack_sig_z DILITHIUM_NAMESPACE(pack_sig_z)
void pack_sig_z(uint8_t sig[CRYPTO_BYTES], const poly* z_elem, unsigned int idx);

#define pack_sig_h DILITHIUM_NAMESPACE(pack_sig_h)
struct pack_sig_h {
  uint8_t* hbuf;
  unsigned int k;
  unsigned int polys_written;
};

#define pack_sig_h_init DILITHIUM_NAMESPACE(pack_sig_h_init)
void pack_sig_h_init(struct pack_sig_h* w, uint8_t* sig);

#define pack_sig_h_update DILITHIUM_NAMESPACE(pack_sig_h_update)
void pack_sig_h_update(struct pack_sig_h* w, const poly* h);

#define pack_sig DILITHIUM_NAMESPACE(pack_sig)
void pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[SEEDBYTES], const polyvecl *z, const polyveck *h);

#define unpack_pk DILITHIUM_NAMESPACE(unpack_pk)
void unpack_pk(uint8_t rho[SEEDBYTES], polyveck *t1, const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);

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

#define unpack_sk DILITHIUM_NAMESPACE(unpack_sk)
void unpack_sk(uint8_t rho[SEEDBYTES],
               uint8_t tr[SEEDBYTES],
               uint8_t key[SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

#define unpack_sig DILITHIUM_NAMESPACE(unpack_sig)
int unpack_sig(uint8_t c[SEEDBYTES], polyvecl *z, polyveck *h, const uint8_t sig[CRYPTO_BYTES]);

#endif

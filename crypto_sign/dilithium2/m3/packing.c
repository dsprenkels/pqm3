#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"

/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/
void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES],
             const uint8_t rho[SEEDBYTES],
             const polyveck *t1)
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES; ++i)
    pk[i] = rho[i];
  pk += SEEDBYTES;

  for(i = 0; i < K; ++i)
    polyt1_pack(pk + i*POLYT1_PACKEDBYTES, &t1->vec[i]);
}

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
void unpack_pk(uint8_t rho[SEEDBYTES],
               polyveck *t1,
               const uint8_t pk[CRYPTO_PUBLICKEYBYTES])
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES; ++i)
    rho[i] = pk[i];
  pk += SEEDBYTES;

  for(i = 0; i < K; ++i)
    polyt1_unpack(&t1->vec[i], pk + i*POLYT1_PACKEDBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t tr[]: byte array containing tr
*              - const uint8_t key[]: byte array containing key
*              - const polyveck *t0: pointer to vector t0
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
**************************************************/
void pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[SEEDBYTES],
             const uint8_t tr[SEEDBYTES],
             const uint8_t key[SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2)
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES; ++i)
    sk[i] = rho[i];
  sk += SEEDBYTES;

  for(i = 0; i < SEEDBYTES; ++i)
    sk[i] = key[i];
  sk += SEEDBYTES;

  for(i = 0; i < SEEDBYTES; ++i)
    sk[i] = tr[i];
  sk += SEEDBYTES;

  for(i = 0; i < L; ++i)
    polyeta_pack(sk + i*POLYETA_PACKEDBYTES, &s1->vec[i]);
  sk += L*POLYETA_PACKEDBYTES;

  for(i = 0; i < K; ++i)
    polyeta_pack(sk + i*POLYETA_PACKEDBYTES, &s2->vec[i]);
  sk += K*POLYETA_PACKEDBYTES;

  for(i = 0; i < K; ++i)
    polyt0_pack(sk + i*POLYT0_PACKEDBYTES, &t0->vec[i]);
}

void unpack_sk_rho(uint8_t rho[SEEDBYTES], const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  const uint8_t* sk_rho = &sk[0];
  for (unsigned i = 0; i < SEEDBYTES; i++) {
    rho[i] = sk_rho[i];
  }
}

void unpack_sk_key(uint8_t key[SEEDBYTES], const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  const uint8_t* sk_key = &sk[SEEDBYTES];
  for (unsigned i = 0; i < SEEDBYTES; i++) {
    key[i] = sk_key[i];
  }
}

void unpack_sk_tr(uint8_t tr[SEEDBYTES], const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  const uint8_t* sk_tr = &sk[2 * SEEDBYTES];
  for (unsigned i = 0; i < SEEDBYTES; i++) {
    tr[i] = sk_tr[i];
  }
}

void unpack_sk_s1(poly* s1_elem, unsigned int idx, const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  const uint8_t* sk_s1 = &sk[3 * SEEDBYTES];
  polyeta_unpack(s1_elem, &sk_s1[idx * POLYETA_PACKEDBYTES]);
}

void unpack_sk_s2(poly* s2_elem, unsigned int idx, const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  const uint8_t* sk_s2 = &sk[3 * SEEDBYTES + L * POLYETA_PACKEDBYTES];
  polyeta_unpack(s2_elem, &sk_s2[idx * POLYETA_PACKEDBYTES]);
}

void unpack_sk_t0(poly* t0_elem, unsigned int idx, const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  const uint8_t* sk_t0 = &sk[3 * SEEDBYTES + (L + K) * POLYETA_PACKEDBYTES];
  polyt0_unpack(t0_elem, &sk_t0[idx * POLYT0_PACKEDBYTES]);
}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t tr[]: output byte array for tr
*              - const uint8_t key[]: output byte array for key
*              - const polyveck *t0: pointer to output vector t0
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
void unpack_sk(uint8_t rho[SEEDBYTES],
               uint8_t tr[SEEDBYTES],
               uint8_t key[SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  unpack_sk_rho(rho, sk);
  unpack_sk_key(key, sk);
  unpack_sk_tr(tr, sk);
  for (unsigned int i = 0; i < L; i++)
  {
    unpack_sk_s1(&s1->vec[i], i, sk);
  }
  for(unsigned int i = 0; i < K; i++) {
    unpack_sk_s2(&s2->vec[i], i, sk);
  }
  for(unsigned int i = 0; i < K; i++) {
    unpack_sk_t0(&t0->vec[i], i, sk);
  }
}

void pack_sig_c(uint8_t sig[CRYPTO_BYTES],
                       const uint8_t c[SEEDBYTES])
{
  uint8_t *c_sig = &sig[0];
  for (unsigned int i = 0; i < SEEDBYTES; i++)
  {
    c_sig[i] = c[i];
  }
}                       

void pack_sig_z(uint8_t sig[CRYPTO_BYTES],
                       const poly *z_elem,
                       unsigned int idx)
{
  uint8_t *z_sig = &sig[SEEDBYTES];
  polyz_pack(&z_sig[idx * POLYZ_PACKEDBYTES], z_elem);
}

void pack_sig_h_init(struct pack_sig_h *w, uint8_t *sig)
{
  w->hbuf = &sig[SEEDBYTES + L * POLYZ_PACKEDBYTES];
  w->k = 0;
  w->polys_written = 0;

  for (unsigned int i = 0; i < OMEGA + K; i++) {
    w->hbuf[i] = 0;
  }
}

void pack_sig_h_update(struct pack_sig_h *w, const poly *h)
{
  for (unsigned int i = 0; i < N; i++) {
    if (h->coeffs[i] != 0) {
      w->hbuf[w->k++] = i;
    }
  }
  w->hbuf[OMEGA + w->polys_written] = w->k;
  w->polys_written++;
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length SEEDBYTES
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
**************************************************/
void pack_sig(uint8_t sig[CRYPTO_BYTES],
              const uint8_t c[SEEDBYTES],
              const polyvecl *z,
              const polyveck *h)
{
  pack_sig_c(sig, c);
  for (unsigned int i = 0; i < L; i++) {
    pack_sig_z(sig, &z->vec[i], i);
  }

  /* Encode h */
  struct pack_sig_h pack_sig_h;
  pack_sig_h_init(&pack_sig_h, sig);
  for(unsigned int i = 0; i < K; i++) {
    pack_sig_h_update(&pack_sig_h, &h->vec[i]);
  }
}

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - uint8_t *c: pointer to output challenge hash
*              - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int unpack_sig(uint8_t c[SEEDBYTES],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig[CRYPTO_BYTES])
{
  unsigned int i, j, k;

  for(i = 0; i < SEEDBYTES; ++i)
    c[i] = sig[i];
  sig += SEEDBYTES;

  for(i = 0; i < L; ++i)
    polyz_unpack(&z->vec[i], sig + i*POLYZ_PACKEDBYTES);
  sig += L*POLYZ_PACKEDBYTES;

  /* Decode h */
  k = 0;
  for(i = 0; i < K; ++i) {
    for(j = 0; j < N; ++j)
      h->vec[i].coeffs[j] = 0;

    if(sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA)
      return 1;

    for(j = k; j < sig[OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > k && sig[j] <= sig[j-1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }

    k = sig[OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = k; j < OMEGA; ++j)
    if(sig[j])
      return 1;

  return 0;
}

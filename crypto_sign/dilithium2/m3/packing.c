#include "params.h"
#include "packing.h"
#include "poly.h"

void pack_pk_rho(uint8_t pk[CRYPTO_PUBLICKEYBYTES], const uint8_t rho[SEEDBYTES])
{
  uint8_t* pk_rho = &pk[0];
  for (unsigned int i = 0; i < SEEDBYTES; i++) {
    pk_rho[i] = rho[i];
  }
}

void pack_pk_t1(uint8_t pk[CRYPTO_PUBLICKEYBYTES], const poly* t1_elem, unsigned int idx)
{
  uint8_t* pk_t1 = &pk[SEEDBYTES];
  polyt1_pack(&pk_t1[idx * POLYT1_PACKEDBYTES], t1_elem);
}

void unpack_pk_rho(uint8_t rho[SEEDBYTES], const uint8_t pk[CRYPTO_PUBLICKEYBYTES])
{
  const uint8_t *pk_rho = &pk[0];
  for (unsigned int i = 0; i < SEEDBYTES; i++) {
    rho[i] = pk_rho[i];
  }
}

void unpack_pk_t1(poly *t1_elem, unsigned int idx, const uint8_t pk[CRYPTO_PUBLICKEYBYTES])
{
  const uint8_t *pk_t1 = &pk[SEEDBYTES];
  polyt1_unpack(t1_elem, &pk_t1[idx * POLYT1_PACKEDBYTES]);
}

void pack_sk_rho(uint8_t sk[CRYPTO_SECRETKEYBYTES], const uint8_t rho[SEEDBYTES])
{
  uint8_t *sk_rho = &sk[0];
  for (unsigned int i = 0; i < SEEDBYTES; i++) {
    sk_rho[i] = rho[i];
  }
}

void pack_sk_key(uint8_t sk[CRYPTO_SECRETKEYBYTES], const uint8_t key[SEEDBYTES])
{
  uint8_t *sk_key = &sk[SEEDBYTES];
  for (unsigned int i = 0; i < SEEDBYTES; i++) {
    sk_key[i] = key[i];
  }
}

void pack_sk_tr(uint8_t sk[CRYPTO_SECRETKEYBYTES], const uint8_t tr[SEEDBYTES])
{
  uint8_t *sk_tr = &sk[2 * SEEDBYTES];
  for (unsigned int i = 0; i < SEEDBYTES; i++) {
    sk_tr[i] = tr[i];
  }
}

void pack_sk_s1(uint8_t sk[CRYPTO_SECRETKEYBYTES], const poly *s1_elem, unsigned int idx)
{
  uint8_t *sk_s1 = &sk[3 * SEEDBYTES];
  polyeta_pack(&sk_s1[idx * POLYETA_PACKEDBYTES], s1_elem);
}

void pack_sk_s2(uint8_t sk[CRYPTO_SECRETKEYBYTES], const poly *s2_elem, unsigned int idx)
{
  uint8_t *sk_s2 = &sk[3 * SEEDBYTES + L * POLYETA_PACKEDBYTES];
  polyeta_pack(&sk_s2[idx * POLYETA_PACKEDBYTES], s2_elem);
}

void pack_sk_t0(uint8_t sk[CRYPTO_SECRETKEYBYTES], const poly *t0_elem, unsigned int idx)
{
  uint8_t *sk_t0 = &sk[3 * SEEDBYTES + (L + K) * POLYETA_PACKEDBYTES];
  polyt0_pack(&sk_t0[idx * POLYT0_PACKEDBYTES], t0_elem);
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

void unpack_sig_c(uint8_t c[SEEDBYTES],
                  const uint8_t sig[CRYPTO_BYTES])
{
  const uint8_t *sig_c = &sig[0];
  for(unsigned int i = 0; i < SEEDBYTES; i++) {
    c[i] = sig_c[i];
  }
}

void unpack_sig_z(poly *z_elem,
                  unsigned int idx,
                  const uint8_t sig[CRYPTO_BYTES])
{
  const uint8_t *sig_z = &sig[SEEDBYTES];
  polyz_unpack(z_elem, &sig_z[idx * POLYZ_PACKEDBYTES]);
}

void unpack_sig_h_init(struct unpack_sig_h *r, const uint8_t *sig)
{
  r->hbuf = &sig[SEEDBYTES + L * POLYZ_PACKEDBYTES];
  r->k = 0;
  r->polys_read = 0;
  r->finished = false;
  r->error = false;
}

int unpack_sig_h_update(struct unpack_sig_h *r, poly *h_elem)
{
  if (r->error) {
    return -1;
  }

  if (r->finished) {
    /* Invalid call to this function */
    r->error = true;
    return -1;
  }

  if (r->hbuf[OMEGA + r->polys_read] < r->k || r->hbuf[OMEGA + r->polys_read] > OMEGA) {
    r->error = true;
    return -1;
  }

  poly_zero(h_elem);
  for (unsigned int i = r->k; i < r->hbuf[OMEGA + r->polys_read]; i++) {
    /* Coefficients are ordered for strong unforgeability */
    if(i > r->k && r->hbuf[i] <= r->hbuf[i-1]) {
      return 1;
    }
    h_elem->coeffs[r->hbuf[i]] = 1;
  }

  r->k = r->hbuf[OMEGA + r->polys_read];
  r->polys_read++;

  if (r->polys_read == K)
  {
    /* Extra indices are zero for strong unforgeability */
    for (unsigned int i = r->k; i < OMEGA; i++) {
      if (r->hbuf[i]) {
        r->error = true;
        return 1;
      }
    }
    r->finished = true;
  }

  return 0;
}

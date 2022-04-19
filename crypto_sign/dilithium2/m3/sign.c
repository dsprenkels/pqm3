#include <stdint.h>
#include <stdbool.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"

int crypto_sign_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t seed[SEEDBYTES])
{
  uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
  uint8_t tr[SEEDBYTES];
  const uint8_t *rho, *rhoprime, *key;

  /* Get randomness for rho, rhoprime and key */
  shake256(seedbuf, 2*SEEDBYTES + CRHBYTES, seed, SEEDBYTES);
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES;
  key = rhoprime + CRHBYTES;

  /* Write seeds to secret & public keys */
  pack_sk_rho(sk, rho);
  pack_pk_rho(pk, rho);
  pack_sk_key(sk, key);

  for (unsigned int i = 0; i < K; i++) {
    poly t1_elem;

    /* Matrix-vector multiplication */
    for (unsigned int j = 0; j < N; j++) {
      t1_elem.coeffs[j] = 0;
    }
    for (unsigned int j = 0; j < L; j++) {
      poly s1_elem, mat_elem;
      poly_uniform_eta(&s1_elem, rhoprime, j);
      if (i == 0) {
        // Write s1 to secret key buffer
        pack_sk_s1(sk, &s1_elem, j);
      }
      poly_ntt(&s1_elem);
      poly_uniform(&mat_elem, rho, (i << 8) | j);
      poly_pointwise_acc_montgomery(&t1_elem, &mat_elem, &s1_elem);
    }
    poly_reduce(&t1_elem);
    poly_invntt_tomont(&t1_elem);

    {
      /* Add error vector s2 */
      poly s2_elem;
      poly_uniform_eta(&s2_elem, rhoprime, L + i);
      pack_sk_s2(sk, &s2_elem, i);
      poly_add(&t1_elem, &t1_elem, &s2_elem);
    }

    {
      /* Extract t1 and write to key buffers */
      poly t0_elem;
      poly_caddq(&t1_elem);
      poly_power2round(&t1_elem, &t0_elem, &t1_elem);
      pack_sk_t0(sk, &t0_elem, i);
      pack_pk_t1(pk, &t1_elem, i);
    }
  }

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk_tr(sk, tr);

  return 0;
}

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
  uint8_t seed[SEEDBYTES];

  if (0 != randombytes(seed, SEEDBYTES)) {
    /* Failed to get randomness from the platform */
    return -1;
  }

  return crypto_sign_keypair_from_seed(pk, sk, seed);
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk)
{
  uint8_t seedbuf[3*SEEDBYTES + 2*CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyveck w;
  poly cp;
  shake256incctx state;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + SEEDBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;

  unpack_sk_rho(rho, sk);
  unpack_sk_tr(tr, sk);
  unpack_sk_key(key, sk);

  /* Compute CRH(tr, msg) */
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, tr, SEEDBYTES);
  shake256_inc_absorb(&state, m, mlen);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
#else
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);
#endif

  for (;;) {
    bool abort = false;

    /* Matrix-vector multiplication */
    for (unsigned int i = 0; i < K; ++i) {
      {
        poly y_elem, mat_elem;
        poly_uniform_gamma1(&y_elem, rhoprime, L * nonce + 0);
        poly_ntt(&y_elem);
        poly_uniform(&mat_elem, rho, (i << 8) | 0);
        poly_pointwise_montgomery(&w.vec[i], &mat_elem, &y_elem);
        for (unsigned int j = 1; j < L; ++j) {
          poly_uniform_gamma1(&y_elem, rhoprime, L * nonce + j);
          poly_ntt(&y_elem);
          poly_uniform(&mat_elem, rho, (i << 8) | j);
          poly_pointwise_acc_montgomery(&w.vec[i], &mat_elem, &y_elem);
        }
      }

      poly_reduce(&w.vec[i]);
      poly_invntt_tomont(&w.vec[i]);

      {
        /* Decompose w and call the random oracle */
        poly w0_elem, w1_elem;
        poly_caddq(&w.vec[i]);
        poly_decompose(&w1_elem, &w0_elem, &w.vec[i]);
        polyw1_pack(&sig[i*POLYW1_PACKEDBYTES], &w1_elem);
      }
    }

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    /* Immediately write ctilde to signature */
    shake256_inc_squeeze(sig, SEEDBYTES, &state);
    poly_challenge(&cp, sig);
    poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    for (unsigned int i = 0; i < L; i++)
    {
      poly z_elem;
      {
        poly s1_elem;
        unpack_sk_s1(&s1_elem, i, sk);
        poly_ntt(&s1_elem);
        poly_pointwise_montgomery(&z_elem, &cp, &s1_elem);
        poly_invntt_tomont(&z_elem);
      }
      {
        poly y_elem;
        poly_uniform_gamma1(&y_elem, rhoprime, L * nonce + i);
        poly_add(&z_elem, &z_elem, &y_elem);
      }
      poly_reduce(&z_elem);
      if (poly_chknorm(&z_elem, GAMMA1 - BETA)) {
        abort = true;
        break;
      }

      /* Write z to signature */
      pack_sig_z(sig, &z_elem, i);
    }
    nonce++;
    if (abort) {
      continue;
    }

    /* Prepare writing of hints to signature */
    struct pack_sig_h pack_sig_h;
    pack_sig_h_init(&pack_sig_h, sig);

    unsigned int hint_popcount = 0;
    for (unsigned int i = 0; i < K; i++) {
      poly w0_elem, w1_elem, h_elem;
      poly_decompose(&w1_elem, &w0_elem, &w.vec[i]);

      /* Check that subtracting cs2 does not change high bits of w and low bits
      do not reveal secret information */
      {
        poly s2_elem;
        unpack_sk_s2(&s2_elem, i, sk);
        poly_ntt(&s2_elem);
        poly_pointwise_montgomery(&h_elem, &cp, &s2_elem);
      }
      poly_invntt_tomont(&h_elem);
      poly_sub(&w0_elem, &w0_elem, &h_elem);
      poly_reduce(&w0_elem);
      if (poly_chknorm(&w0_elem, GAMMA2 - BETA)) {
        abort = true;
        break;
      }

      /* Compute hints for w1 */
      poly t0_elem;
      unpack_sk_t0(&t0_elem, i, sk);
      poly_ntt(&t0_elem);
      poly_pointwise_montgomery_leaktime(&h_elem, &cp, &t0_elem);
      poly_invntt_tomont_leaktime(&h_elem);
      poly_reduce(&h_elem);
      if (poly_chknorm(&h_elem, GAMMA2)) {
        abort = true;
        break;
      }
      poly_add(&w0_elem, &w0_elem, &h_elem);
      hint_popcount += poly_make_hint(&h_elem, &w0_elem, &w1_elem);
      if (hint_popcount > OMEGA) {
        abort = true;
        break;
      }

      /* Encode h */
      pack_sig_h_update(&pack_sig_h, &h_elem);
    }
    if (abort) {
      continue;
    }

    *siglen = CRYPTO_BYTES;
    return 0;
  }
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *sk)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
  *smlen += mlen;
  return 0;
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[K*POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[SEEDBYTES];
  uint8_t c2[SEEDBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
  shake256incctx state;

  if(siglen != CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(c, &z, &h, sig))
    return -1;
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Compute CRH(h(rho, t1), msg) */
  shake256(mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, mu, SEEDBYTES);
  shake256_inc_absorb(&state, m, mlen);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(mu, CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt_leaktime(&z);
  polyvec_matrix_pointwise_montgomery_leaktime(&w1, mat, &z);

  poly_ntt_leaktime(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt_leaktime(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont_leaktime(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, mu, CRHBYTES);
  shake256_inc_absorb(&state, buf, K*POLYW1_PACKEDBYTES);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(c2, SEEDBYTES, &state);
  for(i = 0; i < SEEDBYTES; ++i)
    if(c[i] != c2[i])
      return -1;

  return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *pk)
{
  size_t i;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;
  if(crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}

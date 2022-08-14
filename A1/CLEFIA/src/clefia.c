///////////////////////////////////////////////////////////////////////////////
//  clefia.c
//
//  Implementation of the 128-bit Blockcipher CLEFIA by SONY Corporation
//
//  Done as part of CS6630: Secure Processor µArch (Fall 2022)
//
//  Authors:
//  	Akilesh Kannan (EE18B122)
//  	Arjun Menon V. (EE18B104)
//
///////////////////////////////////////////////////////////////////////////////

#include "clefia.h"
#include <stdio.h>
#include <stdlib.h>

/************************************************/
/************************************************/
/*          Static Function declarations        */
/************************************************/
/************************************************/
static uint8 multBy2(uint8 x);
static uint8 multBy4(uint8 x);
static uint8 multBy6(uint8 x);
static uint8 multBy8(uint8 x);
static uint8 multByA(uint8 x);
static void generateTTable(uint32 *table, tableType type);

static void f0(uint8 *y, const uint8 *x, const uint8 *rk);
static void f1(uint8 *y, const uint8 *x, const uint8 *rk);
static void gfn4(uint8 *y, const uint8 *x, const uint8 *rk, int32 r);
static void gfn4Inv(uint8 *y, const uint8 *x, const uint8 *rk, int32 r);

static void doubleSwap(uint8 *lk);

static void conSet(uint8 *con, const uint8 *iv, int32 lk);

/************************************************/
/************************************************/
/*              Function definitions            */
/************************************************/
/************************************************/
void keySet(uint8 *rk, const uint8 *skey)
{
  const uint8 iv[2] = {0x42U, 0x8aU}; /* cubic root of 2 */
  uint8 lk[16];
  uint8 con128[4 * 60];
  int32 i;

  /* generating CONi^(128) (0 <= i < 60, lk = 30) */
  conSet(con128, iv, 30);
  /* GFN_{4,12} (generating L from K) */
  gfn4(lk, skey, con128, 12);

  byteCpy(rk, skey, 8); /* initial whitening key (WK0, WK1) */
  rk += 8;
  for(i = 0; i < 9; i++){ /* round key (RKi (0 <= i < 36)) */
    byteXor(rk, lk, con128 + i * 16 + (4 * 24), 16);
    if(i % 2){
      byteXor(rk, rk, skey, 16); /* Xoring K */
    }
    doubleSwap(lk); /* Updating L (DoubleSwap function) */
    rk += 16;
  }
  byteCpy(rk, skey + 8, 8); /* final whitening key (WK2, WK3) */
}

void encrypt(uint8 *ct, const uint8 *pt, const uint8 *rk, const int32 r)
{
  uint8 rin[16], rout[16];

  byteCpy(rin,  pt,  16);

  byteXor(rin + 4,  rin + 4,  rk + 0, 4); /* initial key whitening */
  byteXor(rin + 12, rin + 12, rk + 4, 4);
  rk += 8;

  gfn4(rout, rin, rk, r); /* GFN_{4,r} */

  byteCpy(ct, rout, 16);
  byteXor(ct + 4,  ct + 4,  rk + r * 8 + 0, 4); /* final key whitening */
  byteXor(ct + 12, ct + 12, rk + r * 8 + 4, 4);
}

void decrypt(uint8 *pt, const uint8 *ct, const uint8 *rk, const int32 r)
{
  uint8 rin[16], rout[16];

  byteCpy(rin, ct, 16);

  byteXor(rin + 4,  rin + 4,  rk + r * 8 + 8,  4); /* initial key whitening */
  byteXor(rin + 12, rin + 12, rk + r * 8 + 12, 4);
  rk += 8;

  gfn4Inv(rout, rin, rk, r); /* GFN^{-1}_{4,r} */

  byteCpy(pt, rout, 16);
  byteXor(pt + 4,  pt + 4,  rk - 8, 4); /* final key whitening */
  byteXor(pt + 12, pt + 12, rk - 4, 4);
}

void bytePut(const uint8 *data, int32 bytelen){
  while(bytelen-- > 0){
    printf("%02x", *data++);
  }
  printf("\n");
}

void byteCpy(uint8 *dst, const uint8 *src, int32 bytelen){
  while(bytelen-- > 0){
    *dst++ = *src++;
  }
}

void byteXor(uint8 *dst, const uint8 *a, const uint8 *b, int32 bytelen){
  while(bytelen-- > 0){
    *dst++ = *a++ ^ *b++;
  }
}

/************************************************/
/************************************************/
/*           Static Function definitions        */
/************************************************/
/************************************************/

/********************************************/
/* GF(2^8) Multiplications;                 */
/* p(x) = 0x11D = x^8 + x^4 + x^3 + x^2 + 1 */
/********************************************/

static uint8 multBy2(uint8 x){
  if(x & 0x80U){
    x ^= 0x0eU;
  }
  return ((x << 1) | (x >> 7));
}

static uint8 multBy4(uint8 x){
  return multBy2(multBy2(x));
}

static uint8 multBy6(uint8 x){
  return (multBy2(x) ^ multBy4(x));
}

static uint8 multBy8(uint8 x){
  return multBy2(multBy4(x));
}

static uint8 multByA(uint8 x){
  return (multBy2(x) ^ multBy8(x));
}

/***********************/
/* T-Table Generators  */
/***********************/

static void generateTTable(uint32 *table, tableType type){
  int32 i;
  for(i=0;i<256;i+=1){
    switch(type){
      case T_F0_0:
        table[i] = (S0[i] << 24) | (multBy2(S0[i]) << 16) | (multBy4(S0[i]) << 8) | multBy6(S0[i]);
        break;
      case T_F0_1:
        table[i] = (multBy2(S1[i]) << 24) | (S1[i] << 16) | (multBy4(S1[i]) << 8) | multBy6(S1[i]);
        break;
      case T_F0_2:
        table[i] = (multBy4(S1[i]) << 24) | (multBy6(S1[i]) << 16) | (S1[i] << 8) | multBy2(S1[i]);
        break;
      case T_F0_3:
        table[i] = (multBy6(S1[i]) << 24) | (multBy4(S1[i]) << 16) | (multBy2(S1[i]) << 8) | S1[i];
        break;
      case T_F1_0:
        table[i] = (S0[i] << 24) | (multBy8(S0[i]) << 16) | (multBy2(S0[i]) << 8) | multByA(S0[i]);
        break;
      case T_F1_1:
        table[i] = (multBy8(S1[i]) << 24) | (S1[i] << 16) | (multByA(S1[i]) << 8) | multBy2(S1[i]);
        break;
      case T_F1_2:
        table[i] = (multBy2(S1[i]) << 24) | (multByA(S1[i]) << 16) | (S1[i] << 8) | multBy8(S1[i]);
        break;
      case T_F1_3:
        table[i] = (multByA(S1[i]) << 24) | (multBy2(S1[i]) << 16) | (multBy8(S1[i]) << 8) | S1[i];
        break;
      default:
        table = NULL;
        break;
    }
  }
}

static void f0(uint8 *dst, const uint8 *src, const uint8 *rk)
{
  uint8 x[4], y[4], z[4];

  /* Key addition */
  byteXor(x, src, rk, 4);
  /* Substitution layer */
  z[0] = S0[x[0]];
  z[1] = S1[x[1]];
  z[2] = S0[x[2]];
  z[3] = S1[x[3]];
  /* Diffusion layer (M0) */
  y[0] =            z[0]  ^ multBy2(z[1]) ^ multBy4(z[2]) ^ multBy6(z[3]);
  y[1] = multBy2(z[0]) ^            z[1]  ^ multBy6(z[2]) ^ multBy4(z[3]);
  y[2] = multBy4(z[0]) ^ multBy6(z[1]) ^            z[2]  ^ multBy2(z[3]);
  y[3] = multBy6(z[0]) ^ multBy4(z[1]) ^ multBy2(z[2]) ^            z[3] ;

  /* Xoring after F0 */
  byteCpy(dst + 0, src + 0, 4);
  byteXor(dst + 4, src + 4, y, 4);
}

static void f1(uint8 *dst, const uint8 *src, const uint8 *rk)
{
  uint8 x[4], y[4], z[4];

  /* Key addition */
  byteXor(x, src, rk, 4);
  /* Substitution layer */
  z[0] = S1[x[0]];
  z[1] = S0[x[1]];
  z[2] = S1[x[2]];
  z[3] = S0[x[3]];
  /* Diffusion layer (M1) */
  y[0] =            z[0]  ^ multBy8(z[1]) ^ multBy2(z[2]) ^ multByA(z[3]);
  y[1] = multBy8(z[0]) ^            z[1]  ^ multByA(z[2]) ^ multBy2(z[3]);
  y[2] = multBy2(z[0]) ^ multByA(z[1]) ^            z[2]  ^ multBy8(z[3]);
  y[3] = multByA(z[0]) ^ multBy2(z[1]) ^ multBy8(z[2]) ^            z[3] ;

  /* Xoring after F1 */
  byteCpy(dst + 0, src + 0, 4);
  byteXor(dst + 4, src + 4, y, 4);
}

static void gfn4(uint8 *y, const uint8 *x, const uint8 *rk, int32 r)
{
  uint8 fin[16], fout[16];

  byteCpy(fin, x, 16);
  while(r-- > 0){
    f0(fout + 0, fin + 0, rk + 0);
    f1(fout + 8, fin + 8, rk + 4);
    rk += 8;
    if(r){ /* swapping for encryption */
      byteCpy(fin + 0,  fout + 4, 12);
      byteCpy(fin + 12, fout + 0, 4);
    }
  }
  byteCpy(y, fout, 16);
}

static void gfn4Inv(uint8 *y, const uint8 *x, const uint8 *rk, int32 r)
{
  uint8 fin[16], fout[16];

  rk += (r - 1) * 8;
  byteCpy(fin, x, 16);
  while(r-- > 0){
    f0(fout + 0, fin + 0, rk + 0);
    f1(fout + 8, fin + 8, rk + 4);
    rk -= 8;
    if(r){ /* swapping for decryption */
      byteCpy(fin + 0, fout + 12, 4);
      byteCpy(fin + 4, fout + 0,  12);
    }
  }
  byteCpy(y, fout, 16);
}

static void doubleSwap(uint8 *lk)
{
  uint8 t[16];

  t[0]  = (lk[0] << 7) | (lk[1]  >> 1);
  t[1]  = (lk[1] << 7) | (lk[2]  >> 1);
  t[2]  = (lk[2] << 7) | (lk[3]  >> 1);
  t[3]  = (lk[3] << 7) | (lk[4]  >> 1);
  t[4]  = (lk[4] << 7) | (lk[5]  >> 1);
  t[5]  = (lk[5] << 7) | (lk[6]  >> 1);
  t[6]  = (lk[6] << 7) | (lk[7]  >> 1);
  t[7]  = (lk[7] << 7) | (lk[15] & 0x7fU);

  t[8]  = (lk[8]  >> 7) | (lk[0]  & 0xfeU);
  t[9]  = (lk[9]  >> 7) | (lk[8]  << 1);
  t[10] = (lk[10] >> 7) | (lk[9]  << 1);
  t[11] = (lk[11] >> 7) | (lk[10] << 1);
  t[12] = (lk[12] >> 7) | (lk[11] << 1);
  t[13] = (lk[13] >> 7) | (lk[12] << 1);
  t[14] = (lk[14] >> 7) | (lk[13] << 1);
  t[15] = (lk[15] >> 7) | (lk[14] << 1);

  byteCpy(lk, t, 16);
}

static void conSet(uint8 *con, const uint8 *iv, int32 lk)
{
  uint8 t[2];
  uint8 tmp;

  byteCpy(t, iv, 2);
  while(lk-- > 0){
    con[0] = t[0] ^ 0xb7U; /* P_16 = 0xb7e1 (natural logarithm) */
    con[1] = t[1] ^ 0xe1U;
    con[2] = ~((t[0] << 1) | (t[1] >> 7));
    con[3] = ~((t[1] << 1) | (t[0] >> 7));
    con[4] = ~t[0] ^ 0x24U; /* Q_16 = 0x243f (circle ratio) */
    con[5] = ~t[1] ^ 0x3fU;
    con[6] = t[1];
    con[7] = t[0];
    con += 8;

    /* updating T */
    if(t[1] & 0x01U){
      t[0] ^= 0xa8U;
      t[1] ^= 0x30U;
    }
    tmp = t[0] << 7;
    t[0] = (t[0] >> 1) | (t[1] << 7);
    t[1] = (t[1] >> 1) | tmp;
  }
}

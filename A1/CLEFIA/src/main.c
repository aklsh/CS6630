#include "clefia.h"
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
  const uint8 skey[32] = {
    0xffU,0xeeU,0xddU,0xccU,0xbbU,0xaaU,0x99U,0x88U,
    0x77U,0x66U,0x55U,0x44U,0x33U,0x22U,0x11U,0x00U,
    0xf0U,0xe0U,0xd0U,0xc0U,0xb0U,0xa0U,0x90U,0x80U,
    0x70U,0x60U,0x50U,0x40U,0x30U,0x20U,0x10U,0x00U
  };
  const uint8 pt[16] = {
    0x00U,0x01U,0x02U,0x03U,0x04U,0x05U,0x06U,0x07U,
    0x08U,0x09U,0x0aU,0x0bU,0x0cU,0x0dU,0x0eU,0x0fU
  };
  uint8 ct[16];
  uint8 dst[16];
  uint8 rk[8 * 18 + 16]; /* 8 bytes x 18 rounds + whitening keys */
  int32 r;

  printf("--- Test ---\n");
  printf("plaintext:  "); bytePut(pt, 16);
  printf("secretkey:  "); bytePut(skey, 32);

  /* for 128-bit key */
  printf("--- CLEFIA-128 ---\n");
  /* encryption */
  keySet(rk, skey);
  encrypt(dst, pt, rk, 18);
  printf("ciphertext: "); bytePut(dst, 16);
  /* decryption */
  byteCpy(ct, dst, 16);
  keySet(rk, skey);
  decrypt(dst, ct, rk, 18);
  printf("plaintext : "); bytePut(dst, 16);

  return 0;
}


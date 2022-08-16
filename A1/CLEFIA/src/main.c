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
  const uint8 ref[16] = {
    0xdeU,0x2bU,0xf2U,0xfdU,0x9bU,0x74U,0xaaU,0xcdU,
    0xf1U,0x29U,0x85U,0x55U,0x45U,0x94U,0x94U,0xfdU
  };
  uint8 pt[16] = {
    0x00U,0x01U,0x02U,0x03U,0x04U,0x05U,0x06U,0x07U,
    0x08U,0x09U,0x0aU,0x0bU,0x0cU,0x0dU,0x0eU,0x0fU
  };
  uint8 ct[16];
  uint8 dst[16];
  uint8 rk[8 * 18 + 16]; /* 8 bytes x 18 rounds + whitening keys */
  int32 r;

  printf("--- Test ---\n");
  printf("secretkey:  "); bytePut(skey, 32);
  printf("plaintext:  "); bytePut(pt, 16);
  printf("ciphertext: "); bytePut(ref, 16);

  /* for 128-bit key */
  printf("--- CLEFIA-128 ---\n");
  /* encryption */
  keySet(rk, skey);
  clefia_encryption(rk, pt, dst);
  printf("ciphertext: "); bytePut(dst, 16);
  /* decryption */
  byteCpy(ct, dst, 16);
  keySet(rk, skey);
  clefia_decryption(rk, ct, dst);
  printf("plaintext:  "); bytePut(dst, 16);

  int32 i;
  uint8 compare = 0U;
  for(i=0;i<16;i+=1){
    if(ref[i] != ct[i]){
      compare = 1U;
      break;
    }
  }
  if(compare == 0U){
    printf("--- SUCCESS ---\n");
  }
  else{
    printf("--- FAILURE ---\n");
  }

  return 0;
}


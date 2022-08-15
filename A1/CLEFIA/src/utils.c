///////////////////////////////////////////////////////////////////////////////
//  utils.c
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

#include "utils.h"
#include "clefia.h"
#include <stdlib.h>

/********************************************/
/* GF(2^8) Multiplications;                 */
/* p(x) = 0x11D = x^8 + x^4 + x^3 + x^2 + 1 */
/********************************************/

uint8 multBy2(uint8 x){
  if(x & 0x80U){
    x ^= 0x0eU;
  }
  return ((x << 1) | (x >> 7));
}

uint8 multBy4(uint8 x){
  return multBy2(multBy2(x));
}

uint8 multBy6(uint8 x){
  return (multBy2(x) ^ multBy4(x));
}

uint8 multBy8(uint8 x){
  return multBy2(multBy4(x));
}

uint8 multByA(uint8 x){
  return (multBy2(x) ^ multBy8(x));
}

/***********************/
/* T-Table Generators  */
/***********************/

void generateTTable(uint32 *table, tableType type){
  int32 i;
  for(i=0;i<256;i+=1){
    switch(type){
      case T_F0_0:
        table[i] = (S0[i] << 24) | (multBy2(S0[i]) << 16) | (multBy4(S0[i]) << 8) | multBy6(S0[i]);
        break;
      case T_F0_1:
        table[i] = (multBy2(S1[i]) << 24) | (S1[i] << 16) | (multBy6(S1[i]) << 8) | multBy4(S1[i]);
        break;
      case T_F0_2:
        table[i] = (multBy4(S0[i]) << 24) | (multBy6(S0[i]) << 16) | (S0[i] << 8) | multBy2(S0[i]);
        break;
      case T_F0_3:
        table[i] = (multBy6(S1[i]) << 24) | (multBy4(S1[i]) << 16) | (multBy2(S1[i]) << 8) | S1[i];
        break;
      case T_F1_0:
        table[i] = (S1[i] << 24) | (multBy8(S1[i]) << 16) | (multBy2(S1[i]) << 8) | multByA(S1[i]);
        break;
      case T_F1_1:
        table[i] = (multBy8(S0[i]) << 24) | (S0[i] << 16) | (multByA(S0[i]) << 8) | multBy2(S0[i]);
        break;
      case T_F1_2:
        table[i] = (multBy2(S1[i]) << 24) | (multByA(S1[i]) << 16) | (S1[i] << 8) | multBy8(S1[i]);
        break;
      case T_F1_3:
        table[i] = (multByA(S0[i]) << 24) | (multBy2(S0[i]) << 16) | (multBy8(S0[i]) << 8) | S0[i];
        break;
      default:
        table = NULL;
        break;
    }
  }
}

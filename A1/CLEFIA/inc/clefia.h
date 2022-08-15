///////////////////////////////////////////////////////////////////////////////
//  clefia.h
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

#ifndef __CLEFIA_H__
#define __CLEFIA_H__

/***************************** Typedefs *****************************/

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef char int8;
typedef int int32;
typedef enum {
  T_F0_0,
  T_F0_1,
  T_F0_2,
  T_F0_3,
  T_F1_0,
  T_F1_1,
  T_F1_2,
  T_F1_3,
} tableType;

/*********************************************************************/

/***************************** Constants *****************************/

// S0 (8-bit S-box based on four 4-bit S-boxes)
extern const uint8 S0[256];

// S1 (8-bit S-box based on inverse function)
extern const uint8 S1[256];

/*********************************************************************/

/***************************** Functions *****************************/

void keySet(uint8 *rk, const uint8 *skey);
void encrypt(uint8 *ct, const uint8 *pt, const uint8 *rk, const int32 r);
void decrypt(uint8 *pt, const uint8 *ct, const uint8 *rk, const int32 r);

void bytePut(const uint8 *data, int32 bytelen);
void byteCpy(uint8 *dst, const uint8 *src, int32 bytelen);
void byteXor(uint8 *dst, const uint8 *a, const uint8 *b, int32 bytelen);

/*********************************************************************/

#endif

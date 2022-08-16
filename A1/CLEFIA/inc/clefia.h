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

#include "utils.h"

/***************************** Constants *****************************/

// S0 (8-bit S-box based on four 4-bit S-boxes)
extern const uint8 S0[256];

// S1 (8-bit S-box based on inverse function)
extern const uint8 S1[256];

/*********************************************************************/

/***************************** Functions *****************************/

void keySet(uint8 *rk, const uint8 *skey);
void clefia_encryption(uint8 *rk, uint8 *pt, uint8 *ct);
void clefia_decryption(uint8 *rk, uint8 *ct, uint8 *pt);

void bytePut(const uint8 *data, int32 bytelen);
void byteCpy(uint8 *dst, const uint8 *src, int32 bytelen);
void byteXor(uint8 *dst, const uint8 *a, const uint8 *b, int32 bytelen);

/*********************************************************************/

#endif

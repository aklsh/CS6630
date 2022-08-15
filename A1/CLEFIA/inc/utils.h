///////////////////////////////////////////////////////////////////////////////
//  utils.h
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

#ifndef __CLEFIA_UTILS_H__
#define __CLEFIA_UTILS_H__

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

/***************************** Functions *****************************/

uint8 multBy2(uint8 x);
uint8 multBy4(uint8 x);
uint8 multBy6(uint8 x);
uint8 multBy8(uint8 x);
uint8 multByA(uint8 x);
void generateTTable(uint32 *table, tableType type);

/*********************************************************************/

#endif

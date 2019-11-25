/* tee_api_arith_mp.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Implementation of TEE Arithmetic based on libtom mp_ API's,
 * such as used with wolfSSL */

#ifdef WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/integer.h>
#else
#error Must add libtom mp_ API reference
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <tee_api.h>
#include <tee_arith_internal.h>
#include <utee_defines.h>
#include <utee_syscalls.h>
#include <util.h>

/* FMM = Fast Modular Multiplication */

/*************************************************************
 * PANIC
 *************************************************************/

/*
 * TEE_BigInt_Panic
 *
 * This is a temporary solution for testing the TEE_BigInt lib
 */
static void __attribute__ ((noreturn)) TEE_BigInt_Panic(const char *msg)
{
	printf("PANIC: %s\n", msg);
	TEE_Panic(0xB16127 /*BIGINT*/);
	while (1)
		; /* Panic will crash the thread */
}

/*************************************************************
 * INTERNAL FUNCTIONS
 *************************************************************/


/*************************************************************
 * API's
 *************************************************************/

void _TEE_MathAPI_Init(void)
{

}

/* size of mp_int with number of bits, aligned to 32-bits */
uint32_t TEE_BigIntSizeInU32(uint32_t numBits)
{
    uint32_t res = sizeof(mp_int);
    (void)numBits;
    res = ((res + 31) / 32); /* round up to next uint32_t */
    return res;
}

void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len)
{
    (void)len; /* dynamic */
    if (bigInt) {
        mp_init((mp_int*)bigInt);
    }
}

static void TEE_BigIntClear(TEE_BigInt *bigInt)
{
    if (bigInt) {
        mp_clear((mp_int*)bigInt);
    }
}

TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest,
					    const uint8_t *buffer,
					    uint32_t bufferLen, int32_t sign)
{
    int32_t rc;
    mp_int* mpi = (mp_int*)dest;

    if (dest == NULL || buffer == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rc = mp_read_unsigned_bin(mpi, buffer, bufferLen);
    if (rc != MP_OKAY) {
        return TEE_ERROR_OVERFLOW;
    }
    mpi->sign = (sign < 0) ? MP_NEG : MP_ZPOS;

	return TEE_SUCCESS;
}

TEE_Result TEE_BigIntConvertToOctetString(uint8_t *buffer, uint32_t *bufferLen,
					  const TEE_BigInt *bigInt)
{
    int32_t rc;
	mp_int* mpi = (mp_int*)bigInt;

    if (buffer == NULL || bufferLen == NULL || bigInt == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rc = mp_to_unsigned_bin_len(mpi, buffer, (int)*bufferLen);
    if (rc < 0) {
        return TEE_ERROR_SHORT_BUFFER;
    }
    *bufferLen = rc;

	return TEE_SUCCESS;
}

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal)
{
    mp_int* mpi = (mp_int*)dest;
    int32_t rc;
    unsigned long tmpVal;

    if (dest == NULL) {
        TEE_BigInt_Panic("TEE_BigIntConvertFromS32: bad parameter");
        return;
    }

    /* make positive */
    tmpVal = (shortVal < 0) ? -shortVal : shortVal;
    rc = mp_set_int(mpi, tmpVal);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntConvertFromS32: error");
        return;
    }
    /* set sign */
    if (shortVal < 0) {
        mpi->sign = MP_NEG;
    }
}

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, const TEE_BigInt *src)
{
    mp_int* mpi = (mp_int*)src;
    int32_t rc, isNeg = 0, tmpVal = 0;

    if (dest == NULL || src == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* get sign */
    if (mpi->sign == MP_NEG) {
        isNeg = 1;
        mpi->sign = 0;
    }

    rc = mp_to_unsigned_bin_len(mpi, (unsigned char*)&tmpVal, sizeof(tmpVal));
    if (rc < 0) {
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* set sign */
    if (isNeg) {
        tmpVal = -tmpVal;
    }
    *dest = tmpVal;

	return TEE_SUCCESS;
}

int32_t TEE_BigIntCmp(const TEE_BigInt *op1, const TEE_BigInt *op2)
{
    int32_t rc;
    mp_int* mp1 = (mp_int*)op1;
    mp_int* mp2 = (mp_int*)op2;

    if (op1 == NULL || op2 == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rc = mp_cmp(mp1, mp2);
    return rc;
}

int32_t TEE_BigIntCmpS32(const TEE_BigInt *op, int32_t shortVal)
{
    int32_t rc;
    mp_int tmpMp;
    TEE_BigInt* tmpBi = (TEE_BigInt*)&tmpMp;

    if (op == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_BigIntInit(tmpBi, sizeof(int32_t));
    TEE_BigIntConvertFromS32(tmpBi, shortVal);
    rc = TEE_BigIntCmp(op, tmpBi);
    TEE_BigIntClear(tmpBi);

	return rc;
}

void TEE_BigIntShiftRight(TEE_BigInt *dest, const TEE_BigInt *op, size_t bits)
{
    int32_t rc;
    mp_int* mpDst = (mp_int*)dest;
    mp_int* mpOp = (mp_int*)op;

    if (dest == NULL || op == NULL) {
        TEE_BigInt_Panic("TEE_BigIntShiftRight: args");
        return;
    }

    /* if src and dst are same, nothing is done here */
    rc = mp_copy(mpOp, mpDst);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntShiftRight: error");
        return;
    }

    mp_rshb(mpDst, bits);
}

bool TEE_BigIntGetBit(const TEE_BigInt *src, uint32_t bitIndex)
{
	bool rc;
    mp_int* mpSrc = (mp_int*)src;

    if (src == NULL) {
        TEE_BigInt_Panic("TEE_BigIntGetBit: args");
        return (bool)0;
    }

    rc = mp_is_bit_set(mpSrc, bitIndex);

	return rc;
}

uint32_t TEE_BigIntGetBitCount(const TEE_BigInt *src)
{
	uint32_t rc;
    mp_int* mpSrc = (mp_int*)src;

    if (src == NULL) {
        TEE_BigInt_Panic("TEE_BigIntGetBitCount: args");
        return 0;
    }

    rc = mp_count_bits(mpSrc);

	return rc;
}

/* function computes dest = op1 + op2. All or some of dest, op1, and op2 MAY
    point to the same memory region */
void TEE_BigIntAdd(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
    int32_t rc;
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpop1 = (mp_int*)op1;
    mp_int* mpop2 = (mp_int*)op2;

    if (dest == NULL || op1 == NULL || op2 == NULL) {
        TEE_BigInt_Panic("TEE_BigIntAdd: args");
        return;
    }

    rc = mp_add(mpop1, mpop2, mpdest);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntAdd: error");
    }
}

/* function computes dest = op1 – op2. All or some of dest, op1, and op2 MAY
    point to the same memory region */
void TEE_BigIntSub(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
    int32_t rc;
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpop1 = (mp_int*)op1;
    mp_int* mpop2 = (mp_int*)op2;

    if (dest == NULL || op1 == NULL || op2 == NULL) {
        TEE_BigInt_Panic("TEE_BigIntSub: args");
        return;
    }

    rc = mp_sub(mpop1, mpop2, mpdest);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntSub: error");
    }
}

/* function negates an operand: dest=-op. dest and op MAY point to the same */
void TEE_BigIntNeg(TEE_BigInt *dest, const TEE_BigInt *src)
{
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpsrc = (mp_int*)src;

    if (dest == NULL || src == NULL) {
        TEE_BigInt_Panic("TEE_BigIntNeg: args");
        return;
    }

    /* make copy - if not same */
    if (mpsrc != mpdest) {
        mp_copy(mpsrc, mpdest);
    }
    /* negate */
    mpdest->sign = (mpdest->sign == MP_ZPOS) ? MP_NEG : MP_ZPOS;
}

/* function computes dest=op1 * op2. All or some of dest, op1, and op2 MAY
    point to the same memory region */
void TEE_BigIntMul(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
    int32_t rc;
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpop1 = (mp_int*)op1;
    mp_int* mpop2 = (mp_int*)op2;

    if (dest == NULL || op1 == NULL || op2 == NULL) {
        TEE_BigInt_Panic("TEE_BigIntMul: args");
        return;
    }

    rc = mp_mul(mpop1, mpop2, mpdest);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntMul: error");
    }
}

void TEE_BigIntSquare(TEE_BigInt *dest, const TEE_BigInt *op)
{
	TEE_BigIntMul(dest, op, op);
}

/* function computes dest_r and dest_q such that op1 = dest_q * op2 + dest_r.
    It will round dest_q towards zero and dest_r will have the same sign as op1 */
void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
		   const TEE_BigInt *op1, const TEE_BigInt *op2)
{
    int32_t rc;
    mp_int* mpdestq = (mp_int*)dest_q;
    mp_int* mpdestr = (mp_int*)dest_r;
    mp_int* mpop1 = (mp_int*)op1;
    mp_int* mpop2 = (mp_int*)op2;

    if (mpdestq == NULL || mpdestr == NULL || op1 == NULL || op2 == NULL) {
        TEE_BigInt_Panic("TEE_BigIntDiv: args");
        return;
    }

    rc = mp_div(mpop1, mpop2, mpdestq, mpdestr);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntDiv: error");
    }
}

/* function computes dest = op (mod n) such that 0 <= dest < n. dest and op MAY
    point to the same memory */
void TEE_BigIntMod(TEE_BigInt *dest, const TEE_BigInt *op, const TEE_BigInt *n)
{
    int32_t rc;
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpop = (mp_int*)op;
    mp_int* mpn = (mp_int*)n;

    if (dest == NULL || op == NULL || n == NULL) {
        TEE_BigInt_Panic("TEE_BigIntMod: args");
        return;
    }

    if (TEE_BigIntCmpS32(n, 2) < 0) {
		TEE_BigInt_Panic("TEE_BigIntMod: Modulus is too short");
    }

    rc = mp_mod(mpop, mpn, mpdest);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntMod: error");
    }
}

/* function computes dest = (op1 + op2) (mod n). All or some of dest, op1, and
    op2 MAY point to the same memory */
void TEE_BigIntAddMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
    int32_t rc;
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpop1 = (mp_int*)op1;
    mp_int* mpop2 = (mp_int*)op2;
    mp_int* mpn = (mp_int*)n;

    if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL) {
        TEE_BigInt_Panic("TEE_BigIntAddMod: args");
        return;
    }

    rc = mp_addmod(mpop1, mpop2, mpn, mpdest);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntAddMod: error");
    }
}

/* function computes dest = (op1 - op2) (mod n). All or some of dest, op1, and
    op2 MAY point to the same memory */
void TEE_BigIntSubMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
    int32_t rc;
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpop1 = (mp_int*)op1;
    mp_int* mpop2 = (mp_int*)op2;
    mp_int* mpn = (mp_int*)n;

    if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL) {
        TEE_BigInt_Panic("TEE_BigIntSubMod: args");
        return;
    }

    rc = mp_submod(mpop1, mpop2, mpn, mpdest);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntSubMod: error");
    }
}

/* function computes dest = (op1 * op2) (mod n). All or some of dest, op1, and
    op2 MAY point to the same memory region */
void TEE_BigIntMulMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
    int32_t rc;
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpop1 = (mp_int*)op1;
    mp_int* mpop2 = (mp_int*)op2;
    mp_int* mpn = (mp_int*)n;

    if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL) {
        TEE_BigInt_Panic("TEE_BigIntMulMod: args");
        return;
    }

    rc = mp_mulmod(mpop1, mpop2, mpn, mpdest);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntMulMod: error");
    }
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, const TEE_BigInt *op,
			 const TEE_BigInt *n)
{
	TEE_BigIntMulMod(dest, op, op, n);
}

void TEE_BigIntInvMod(TEE_BigInt *dest, const TEE_BigInt *op,
		      const TEE_BigInt *n)
{
    int32_t rc;
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpop = (mp_int*)op;
    mp_int* mpn = (mp_int*)n;

    if (dest == NULL || op == NULL || n == NULL) {
        TEE_BigInt_Panic("TEE_BigIntInvMod: args");
        return;
    }

    if (TEE_BigIntCmpS32(n, 2) < 0 || TEE_BigIntCmpS32(op, 0) == 0) {
		TEE_BigInt_Panic("TEE_BigIntInvMod: too small modulus or trying to invert zero");
    }

    rc = mp_invmod(mpop, mpn, mpdest);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntInvMod: error");
    }
}

/* function determines whether gcd(op1, op2) == 1. op1 and op2 MAY point to the
    same memory region */
bool TEE_BigIntRelativePrime(const TEE_BigInt *op1, const TEE_BigInt *op2)
{
    int32_t rc;
    mp_int* mpop1 = (mp_int*)op1;
    mp_int* mpop2 = (mp_int*)op2;
    mp_int mpgcd;

    if (op1 == NULL || op2 == NULL) {
        TEE_BigInt_Panic("TEE_BigIntRelativePrime: args");
        return (bool)0;
    }

    mp_init(&mpgcd);
    rc = mp_gcd(mpop1, mpop2, &mpgcd);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntRelativePrime: error");
        return (bool)0;
    }

    rc = mp_cmp_d(&mpgcd, 1);
    return (rc == MP_EQ);
}

/* function computes the greatest common divisor of the input parameters op1
    and op2. op1 and op2 SHALL NOT both be zero. Furthermore it computes
    coefficients u and v such that u*op1+v*op2==gcd. op1 and op2 MAY point to
    the same memory region */
void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
				  TEE_BigInt *v, const TEE_BigInt *op1,
				  const TEE_BigInt *op2)
{
    int32_t rc;
    mp_int* mpgcd = (mp_int*)gcd;
    mp_int* mpop1 = (mp_int*)op1;
    mp_int* mpop2 = (mp_int*)op2;

    if (u == NULL && v == NULL) {
        rc = mp_gcd(mpop1, mpop2, mpgcd);
        if (rc != MP_OKAY) {
            TEE_BigInt_Panic("TEE_BigIntComputeExtendedGcd: error");
        }
    }
    else {
        /* Not supported */
    }
}

int32_t TEE_BigIntIsProbablePrime(const TEE_BigInt *op,
				  uint32_t confidenceLevel __unused)
{
	int32_t rc, isPrime = 0;
    const int millerRabbins = 8;
	mp_int* mpop = (mp_int*)op;

    rc = mp_prime_is_prime(mpop, millerRabbins, &isPrime);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntIsProbablePrime: error");
    }

	return isPrime;
}

/*
 * Not so fast FMM implementation based on the normal big int functions.
 *
 * Note that these functions (along with all the other functions in this
 * file) only are used directly by the TA doing bigint arithmetics on its
 * own. Performance of RSA operations in TEE Internal API are not affected
 * by this.
 */
void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, uint32_t len)
{
	TEE_BigIntInit(bigIntFMM, len);
}

void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context __unused,
			      uint32_t len __unused,
			      const TEE_BigInt *modulus __unused)
{
}

uint32_t TEE_BigIntFMMSizeInU32(uint32_t modulusSizeInBits)
{
	return TEE_BigIntSizeInU32(modulusSizeInBits);
}

uint32_t TEE_BigIntFMMContextSizeInU32(uint32_t modulusSizeInBits __unused)
{
	/* Return something larger than 0 to keep malloc() and friends happy */
	return 1;
}

void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest, const TEE_BigInt *src,
			    const TEE_BigInt *n,
			    const TEE_BigIntFMMContext *context __unused)
{
	TEE_BigIntMod(dest, src, n);
}

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, const TEE_BigIntFMM *src,
			      const TEE_BigInt *n __unused,
			      const TEE_BigIntFMMContext *context __unused)
{
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpsrc = (mp_int*)src;

    if (src && dest) {
        mp_copy(mpsrc, mpdest);
    }
}

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, const TEE_BigIntFMM *op1,
			  const TEE_BigIntFMM *op2, const TEE_BigInt *n,
			  const TEE_BigIntFMMContext *context __unused)
{
    int32_t rc;
    mp_int* mpdest = (mp_int*)dest;
    mp_int* mpop1 = (mp_int*)op1;
    mp_int* mpop2 = (mp_int*)op2;
    mp_int* mpn = (mp_int*)n;

    if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL) {
        TEE_BigInt_Panic("TEE_BigIntMul: args");
        return;
    }

    rc = mp_mul(mpop1, mpop2, mpdest);
    if (rc != MP_OKAY) {
        TEE_BigInt_Panic("TEE_BigIntMul: error");
    }
    rc = mp_mod(mpdest, mpn, mpdest);
}

// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro limited
 */

/* Implementation of TEE Arithmetic based on libtom mp_ API's,
 * such as used with wolfSSL */

#include <assert.h>
#ifdef WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/integer.h>
#else
#error Must add libtom mp_ API reference
#endif
#include <stdio.h>
#include <string.h>
#include <tee_api.h>
#include <tee_arith_internal.h>
#include <utee_defines.h>
#include <utee_syscalls.h>
#include <util.h>


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

    if (src == NULL) {
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

    rc = mp_cmp(op1, op2);
    return rc;
}

int32_t TEE_BigIntCmpS32(const TEE_BigInt *op, int32_t shortVal)
{
    mp_int tmpMp;
    TEE_BigInt* tmpBi = (TEE_BigInt*)&tmpMp;

    if (op == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_BigIntInit(tmpBi, sizeof(int32_t));
    rc = TEE_BigIntConvertFromS32(tmpBi, shortVal);
    if (rc == TEE_SUCCESS) {
        rc = TEE_BigIntCmp(op, tmpBi);
    }
    TEE_BigIntClear(tmpBi);

	return rc;
}

void TEE_BigIntShiftRight(TEE_BigInt *dest, const TEE_BigInt *op, size_t bits)
{
    int32_t rc;
    mp_int* mpDst = (mp_int*)dest;
    mp_int* mpOp = (mp_int*)op;

    if (dest == NULL || op == NULL) {
        TEE_Panic("TEE_BigIntShiftRight: args");
        return;
    }

    /* if src and dst are same, nothing is done here */
    rc = mp_copy(mpOp, mpDst);
    if (rc == MP_OKAY) {
        rc = mp_rshb(mpDst, bits);
    }
    if (rc != MP_OKAY) {
        TEE_Panic("TEE_BigIntShiftRight: error");
    }
}

bool TEE_BigIntGetBit(const TEE_BigInt *src, uint32_t bitIndex)
{
	bool rc;
	mp_int mpi;

	get_const_mpi(&mpi, src);

	rc = mbedtls_mpi_get_bit(&mpi, bitIndex);

	put_mpi(&mpi);

	return rc;
}

uint32_t TEE_BigIntGetBitCount(const TEE_BigInt *src)
{
	uint32_t rc;
	mp_int mpi;

	get_const_mpi(&mpi, src);

	rc = mbedtls_mpi_bitlen(&mpi);

	put_mpi(&mpi);

	return rc;
}

static void bigint_binary(TEE_BigInt *dest, const TEE_BigInt *op1,
			  const TEE_BigInt *op2,
			  int (*func)(mp_int *X, const mp_int *A,
				      const mp_int *B))
{
	mp_int mpi_dest;
	mp_int mpi_op1;
	mp_int mpi_op2;
	mp_int *pop1 = &mpi_op1;
	mp_int *pop2 = &mpi_op2;

	get_mpi(&mpi_dest, dest);

	if (op1 == dest)
		pop1 = &mpi_dest;
	else
		get_const_mpi(&mpi_op1, op1);

	if (op2 == dest)
		pop2 = &mpi_dest;
	else if (op2 == op1)
		pop2 = pop1;
	else
		get_const_mpi(&mpi_op2, op2);

	MPI_CHECK(func(&mpi_dest, pop1, pop2));

	put_mpi(&mpi_dest);
	if (pop1 == &mpi_op1)
		put_mpi(&mpi_op1);
	if (pop2 == &mpi_op2)
		put_mpi(&mpi_op2);
}

static void bigint_binary_mod(TEE_BigInt *dest, const TEE_BigInt *op1,
			      const TEE_BigInt *op2, const TEE_BigInt *n,
			      int (*func)(mp_int *X, const mp_int *A,
					  const mp_int *B))
{
	if (TEE_BigIntCmpS32(n, 2) < 0)
		API_PANIC("Modulus is too short");

	mp_int mpi_dest;
	mp_int mpi_op1;
	mp_int mpi_op2;
	mp_int mpi_n;
	mp_int *pop1 = &mpi_op1;
	mp_int *pop2 = &mpi_op2;
	mp_int mpi_t;

	get_mpi(&mpi_dest, dest);
	get_const_mpi(&mpi_n, n);

	if (op1 == dest)
		pop1 = &mpi_dest;
	else
		get_const_mpi(&mpi_op1, op1);

	if (op2 == dest)
		pop2 = &mpi_dest;
	else if (op2 == op1)
		pop2 = pop1;
	else
		get_const_mpi(&mpi_op2, op2);

	get_mpi(&mpi_t, NULL);

	MPI_CHECK(func(&mpi_t, pop1, pop2));
	MPI_CHECK(mbedtls_mpi_mod_mpi(&mpi_dest, &mpi_t, &mpi_n));

	put_mpi(&mpi_dest);
	if (pop1 == &mpi_op1)
		put_mpi(&mpi_op1);
	if (pop2 == &mpi_op2)
		put_mpi(&mpi_op2);
	put_mpi(&mpi_t);
}

void TEE_BigIntAdd(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
	bigint_binary(dest, op1, op2, mbedtls_mpi_add_mpi);
}

void TEE_BigIntSub(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
	bigint_binary(dest, op1, op2, mbedtls_mpi_sub_mpi);
}

void TEE_BigIntNeg(TEE_BigInt *dest, const TEE_BigInt *src)
{
	mp_int mpi_dest;

	get_mpi(&mpi_dest, dest);

	if (dest != src) {
		mp_int mpi_src;

		get_const_mpi(&mpi_src, src);

		MPI_CHECK(mbedtls_mpi_copy(&mpi_dest, &mpi_src));

		put_mpi(&mpi_src);
	}

	mpi_dest.s *= -1;

	put_mpi(&mpi_dest);
}

void TEE_BigIntMul(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
	size_t bs1 = TEE_BigIntGetBitCount(op1);
	size_t bs2 = TEE_BigIntGetBitCount(op2);
	size_t s = TEE_BigIntSizeInU32(bs1) + TEE_BigIntSizeInU32(bs2);
	TEE_BigInt zero[TEE_BigIntSizeInU32(1)] = { 0 };
	TEE_BigInt *tmp = NULL;

	tmp = mempool_alloc(mbedtls_mpi_mempool, sizeof(uint32_t) * s);
	if (!tmp)
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	TEE_BigIntInit(tmp, s);
	TEE_BigIntInit(zero, TEE_BigIntSizeInU32(1));

	bigint_binary(tmp, op1, op2, mbedtls_mpi_mul_mpi);

	TEE_BigIntAdd(dest, tmp, zero);

	mempool_free(mbedtls_mpi_mempool, tmp);
}

void TEE_BigIntSquare(TEE_BigInt *dest, const TEE_BigInt *op)
{
	TEE_BigIntMul(dest, op, op);
}

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
		   const TEE_BigInt *op1, const TEE_BigInt *op2)
{
	mp_int mpi_dest_q;
	mp_int mpi_dest_r;
	mp_int mpi_op1;
	mp_int mpi_op2;
	mp_int *pop1 = &mpi_op1;
	mp_int *pop2 = &mpi_op2;

	get_mpi(&mpi_dest_q, dest_q);
	get_mpi(&mpi_dest_r, dest_r);

	if (op1 == dest_q)
		pop1 = &mpi_dest_q;
	else if (op1 == dest_r)
		pop1 = &mpi_dest_r;
	else
		get_const_mpi(&mpi_op1, op1);

	if (op2 == dest_q)
		pop2 = &mpi_dest_q;
	else if (op2 == dest_r)
		pop2 = &mpi_dest_r;
	else if (op2 == op1)
		pop2 = pop1;
	else
		get_const_mpi(&mpi_op2, op2);

	MPI_CHECK(mbedtls_mpi_div_mpi(&mpi_dest_q, &mpi_dest_r, pop1, pop2));

	put_mpi(&mpi_dest_q);
	put_mpi(&mpi_dest_r);
	if (pop1 == &mpi_op1)
		put_mpi(&mpi_op1);
	if (pop2 == &mpi_op2)
		put_mpi(&mpi_op2);
}

void TEE_BigIntMod(TEE_BigInt *dest, const TEE_BigInt *op, const TEE_BigInt *n)
{
	if (TEE_BigIntCmpS32(n, 2) < 0)
		API_PANIC("Modulus is too short");

	bigint_binary(dest, op, n, mbedtls_mpi_mod_mpi);
}

void TEE_BigIntAddMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
	bigint_binary_mod(dest, op1, op2, n, mbedtls_mpi_add_mpi);
}

void TEE_BigIntSubMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
	bigint_binary_mod(dest, op1, op2, n, mbedtls_mpi_sub_mpi);
}

void TEE_BigIntMulMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
	bigint_binary_mod(dest, op1, op2, n, mbedtls_mpi_mul_mpi);
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, const TEE_BigInt *op,
			 const TEE_BigInt *n)
{
	TEE_BigIntMulMod(dest, op, op, n);
}

void TEE_BigIntInvMod(TEE_BigInt *dest, const TEE_BigInt *op,
		      const TEE_BigInt *n)
{
	if (TEE_BigIntCmpS32(n, 2) < 0 || TEE_BigIntCmpS32(op, 0) == 0)
		API_PANIC("too small modulus or trying to invert zero");

	mp_int mpi_dest;
	mp_int mpi_op;
	mp_int mpi_n;
	mp_int *pop = &mpi_op;

	get_mpi(&mpi_dest, dest);
	get_const_mpi(&mpi_n, n);

	if (op == dest)
		pop = &mpi_dest;
	else
		get_const_mpi(&mpi_op, op);

	MPI_CHECK(mbedtls_mpi_inv_mod(&mpi_dest, pop, &mpi_n));

	put_mpi(&mpi_dest);
	put_mpi(&mpi_n);
	if (pop == &mpi_op)
		put_mpi(&mpi_op);
}

bool TEE_BigIntRelativePrime(const TEE_BigInt *op1, const TEE_BigInt *op2)
{
	bool rc;
	mp_int mpi_op1;
	mp_int mpi_op2;
	mp_int *pop2 = &mpi_op2;
	mp_int gcd;

	get_const_mpi(&mpi_op1, op1);

	if (op2 == op1)
		pop2 = &mpi_op1;
	else
		get_const_mpi(&mpi_op2, op2);

	get_mpi(&gcd, NULL);

	MPI_CHECK(mbedtls_mpi_gcd(&gcd, &mpi_op1, &mpi_op2));

	rc = !mbedtls_mpi_cmp_int(&gcd, 1);

	put_mpi(&gcd);
	put_mpi(&mpi_op1);
	if (pop2 == &mpi_op2)
		put_mpi(&mpi_op2);

	return rc;
}

static bool mpi_is_odd(mp_int *x)
{
	return mbedtls_mpi_get_bit(x, 0);
}

static bool mpi_is_even(mp_int *x)
{
	return !mpi_is_odd(x);
}

/*
 * Based on libmpa implementation __mpa_egcd(), modified to work with MPI
 * instead.
 */
static void mpi_egcd(mp_int *gcd, mp_int *a, mp_int *b,
		     mp_int *x_in, mp_int *y_in)
{
	mbedtls_mpi_uint k;
	mp_int A;
	mp_int B;
	mp_int C;
	mp_int D;
	mp_int x;
	mp_int y;
	mp_int u;

	get_mpi(&A, NULL);
	get_mpi(&B, NULL);
	get_mpi(&C, NULL);
	get_mpi(&D, NULL);
	get_mpi(&x, NULL);
	get_mpi(&y, NULL);
	get_mpi(&u, NULL);

	/* have y < x from assumption */
	if (!mbedtls_mpi_cmp_int(y_in, 0)) {
		MPI_CHECK(mbedtls_mpi_lset(a, 1));
		MPI_CHECK(mbedtls_mpi_lset(b, 0));
		MPI_CHECK(mbedtls_mpi_copy(gcd, x_in));
		goto out;
	}

	MPI_CHECK(mbedtls_mpi_copy(&x, x_in));
	MPI_CHECK(mbedtls_mpi_copy(&y, y_in));

	k = 0;
	while (mpi_is_even(&x) && mpi_is_even(&y)) {
		k++;
		MPI_CHECK(mbedtls_mpi_shift_r(&x, 1));
		MPI_CHECK(mbedtls_mpi_shift_r(&y, 1));
	}

	MPI_CHECK(mbedtls_mpi_copy(&u, &x));
	MPI_CHECK(mbedtls_mpi_copy(gcd, &y));
	MPI_CHECK(mbedtls_mpi_lset(&A, 1));
	MPI_CHECK(mbedtls_mpi_lset(&B, 0));
	MPI_CHECK(mbedtls_mpi_lset(&C, 0));
	MPI_CHECK(mbedtls_mpi_lset(&D, 1));

	while (mbedtls_mpi_cmp_int(&u, 0)) {
		while (mpi_is_even(&u)) {
			MPI_CHECK(mbedtls_mpi_shift_r(&u, 1));
			if (mpi_is_odd(&A) || mpi_is_odd(&B)) {
				MPI_CHECK(mbedtls_mpi_add_mpi(&A, &A, &y));
				MPI_CHECK(mbedtls_mpi_sub_mpi(&B, &B, &x));
			}
			MPI_CHECK(mbedtls_mpi_shift_r(&A, 1));
			MPI_CHECK(mbedtls_mpi_shift_r(&B, 1));
		}

		while (mpi_is_even(gcd)) {
			MPI_CHECK(mbedtls_mpi_shift_r(gcd, 1));
			if (mpi_is_odd(&C) || mpi_is_odd(&D)) {
				MPI_CHECK(mbedtls_mpi_add_mpi(&C, &C, &y));
				MPI_CHECK(mbedtls_mpi_sub_mpi(&D, &D, &x));
			}
			MPI_CHECK(mbedtls_mpi_shift_r(&C, 1));
			MPI_CHECK(mbedtls_mpi_shift_r(&D, 1));

		}

		if (mbedtls_mpi_cmp_mpi(&u, gcd) >= 0) {
			MPI_CHECK(mbedtls_mpi_sub_mpi(&u, &u, gcd));
			MPI_CHECK(mbedtls_mpi_sub_mpi(&A, &A, &C));
			MPI_CHECK(mbedtls_mpi_sub_mpi(&B, &B, &D));
		} else {
			MPI_CHECK(mbedtls_mpi_sub_mpi(gcd, gcd, &u));
			MPI_CHECK(mbedtls_mpi_sub_mpi(&C, &C, &A));
			MPI_CHECK(mbedtls_mpi_sub_mpi(&D, &D, &B));
		}
	}

	MPI_CHECK(mbedtls_mpi_copy(a, &C));
	MPI_CHECK(mbedtls_mpi_copy(b, &D));
	MPI_CHECK(mbedtls_mpi_shift_l(gcd, k));

out:
	put_mpi(&A);
	put_mpi(&B);
	put_mpi(&C);
	put_mpi(&D);
	put_mpi(&x);
	put_mpi(&y);
	put_mpi(&u);
}

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
				  TEE_BigInt *v, const TEE_BigInt *op1,
				  const TEE_BigInt *op2)
{
	mp_int mpi_gcd_res;
	mp_int mpi_op1;
	mp_int mpi_op2;
	mp_int *pop2 = &mpi_op2;

	get_mpi(&mpi_gcd_res, gcd);
	get_const_mpi(&mpi_op1, op1);

	if (op2 == op1)
		pop2 = &mpi_op1;
	else
		get_const_mpi(&mpi_op2, op2);

	if (!u && !v) {
		if (gcd)
			MPI_CHECK(mbedtls_mpi_gcd(&mpi_gcd_res, &mpi_op1,
						  pop2));
	} else {
		mp_int mpi_u;
		mp_int mpi_v;
		int8_t s1 = mpi_op1.s;
		int8_t s2 = pop2->s;
		int cmp;

		mpi_op1.s = 1;
		pop2->s = 1;

		get_mpi(&mpi_u, u);
		get_mpi(&mpi_v, v);

		cmp = mbedtls_mpi_cmp_abs(&mpi_op1, pop2);
		if (cmp == 0) {
			MPI_CHECK(mbedtls_mpi_copy(&mpi_gcd_res, &mpi_op1));
			MPI_CHECK(mbedtls_mpi_lset(&mpi_u, 1));
			MPI_CHECK(mbedtls_mpi_lset(&mpi_v, 0));
		} else if (cmp > 0) {
			mpi_egcd(&mpi_gcd_res, &mpi_u, &mpi_v, &mpi_op1, pop2);
		} else {
			mpi_egcd(&mpi_gcd_res, &mpi_v, &mpi_u, pop2, &mpi_op1);
		}

		mpi_u.s *= s1;
		mpi_v.s *= s2;

		put_mpi(&mpi_u);
		put_mpi(&mpi_v);
	}

	put_mpi(&mpi_gcd_res);
	put_mpi(&mpi_op1);
	if (pop2 == &mpi_op2)
		put_mpi(&mpi_op2);
}

static int rng_read(void *ignored __unused, unsigned char *buf, size_t blen)
{
	if (utee_cryp_random_number_generate(buf, blen))
		return MBEDTLS_ERR_MPI_FILE_IO_ERROR;
	return 0;
}

int32_t TEE_BigIntIsProbablePrime(const TEE_BigInt *op,
				  uint32_t confidenceLevel __unused)
{
	int rc;
	mp_int mpi_op;

	get_const_mpi(&mpi_op, op);

	rc = mbedtls_mpi_is_prime(&mpi_op, rng_read, NULL);

	put_mpi(&mpi_op);

	if (rc)
		return 0;

	return 1;
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
	mp_int mpi_dst;
	mp_int mpi_src;

	get_mpi(&mpi_dst, dest);
	get_const_mpi(&mpi_src, src);

	MPI_CHECK(mbedtls_mpi_copy(&mpi_dst, &mpi_src));

	put_mpi(&mpi_dst);
	put_mpi(&mpi_src);
}

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, const TEE_BigIntFMM *op1,
			  const TEE_BigIntFMM *op2, const TEE_BigInt *n,
			  const TEE_BigIntFMMContext *context __unused)
{
	mp_int mpi_dst;
	mp_int mpi_op1;
	mp_int mpi_op2;
	mp_int mpi_n;
	mp_int mpi_t;

	get_mpi(&mpi_dst, dest);
	get_const_mpi(&mpi_op1, op1);
	get_const_mpi(&mpi_op2, op2);
	get_const_mpi(&mpi_n, n);
	get_mpi(&mpi_t, NULL);

	MPI_CHECK(mbedtls_mpi_mul_mpi(&mpi_t, &mpi_op1, &mpi_op2));
	MPI_CHECK(mbedtls_mpi_mod_mpi(&mpi_dst, &mpi_t, &mpi_n));

	put_mpi(&mpi_t);
	put_mpi(&mpi_n);
	put_mpi(&mpi_op2);
	put_mpi(&mpi_op1);
	put_mpi(&mpi_dst);
}

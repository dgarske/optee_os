global-incdirs-y += wolfssl
global-incdirs-y += include

# OBJS_WOLFCRYPT
SRCS_CRYPTO :=
SRCS_CRYPTO += aes.c
#SRCS_CRYPTO += arc4.c
SRCS_CRYPTO += asn.c
#SRCS_CRYPTO += blake2b.c
#SRCS_CRYPTO += blake2s.c
SRCS_CRYPTO += chacha.c
SRCS_CRYPTO += chacha20_poly1305.c
#SRCS_CRYPTO += cmac.c
SRCS_CRYPTO += coding.c
SRCS_CRYPTO += compress.c
SRCS_CRYPTO += cryptocb.c
SRCS_CRYPTO += curve25519.c
SRCS_CRYPTO += des3.c
SRCS_CRYPTO += dh.c
#SRCS_CRYPTO += dsa.c
SRCS_CRYPTO += ecc.c
SRCS_CRYPTO += ed25519.c
SRCS_CRYPTO += error.c
SRCS_CRYPTO += fe_low_mem.c
#SRCS_CRYPTO += fe_operations.c
SRCS_CRYPTO += ge_low_mem.c
#SRCS_CRYPTO += ge_operations.c
SRCS_CRYPTO += hash.c
SRCS_CRYPTO += hmac.c
SRCS_CRYPTO += integer.c
SRCS_CRYPTO += logging.c
#SRCS_CRYPTO += md2.c
#SRCS_CRYPTO += md4.c
SRCS_CRYPTO += md5.c
SRCS_CRYPTO += memory.c
#SRCS_CRYPTO += misc.c
#SRCS_CRYPTO += pkcs7.c
#SRCS_CRYPTO += pkcs12.c
SRCS_CRYPTO += poly1305.c
SRCS_CRYPTO += pwdbased.c
SRCS_CRYPTO += random.c
SRCS_CRYPTO += rsa.c
SRCS_CRYPTO += sha.c
#SRCS_CRYPTO += sha3.c
SRCS_CRYPTO += sha256.c
SRCS_CRYPTO += sha512.c
SRCS_CRYPTO += signature.c
#SRCS_CRYPTO += sp_arm32.c
#SRCS_CRYPTO += sp_arm64.c
#SRCS_CRYPTO += sp_armthumb.c
SRCS_CRYPTO += sp_c32.c
#SRCS_CRYPTO += sp_c64.c
SRCS_CRYPTO += sp_cortexm.c
SRCS_CRYPTO += sp_int.c
#SRCS_CRYPTO += srp.c
SRCS_CRYPTO += tfm.c
SRCS_CRYPTO += wc_encrypt.c
#SRCS_CRYPTO += wc_pkcs11.c
SRCS_CRYPTO += wc_port.c
SRCS_CRYPTO += wolfevent.c
SRCS_CRYPTO += wolfmath.c

# OBJS_WOLFSSL
SRCS_TLS :=
SRCS_TLS += crl.c
SRCS_TLS += internal.c
SRCS_TLS += keys.c
SRCS_TLS += ocsp.c
SRCS_TLS += ssl.c
SRCS_TLS += tls.c
SRCS_TLS += tls13.c
SRCS_TLS += wolfio.c

srcs-y += $(addprefix wolfssl/wolfcrypt/src/, $(SRCS_CRYPTO))
srcs-y += $(addprefix wolfssl/src/, $(SRCS_TLS))

# Kernel headers
cflags-lib-y += -Icore/include
cppflags$(sm) += -Icore/include

# Build settings come from include/user_settings.h
cflags-lib-y += -DWOLFSSL_USER_SETTINGS
cppflags$(sm) += -DWOLFSSL_USER_SETTINGS

#cflags-lib-y += -Wno-redundant-decls
cflags-lib-y += -Wno-switch-default
cflags-lib-y += -Wno-pedantic
cflags-lib-y += -Wno-strict-aliasing
cflags-lib-y += -Wno-aggregate-return
cflags-lib-y += -Wno-cast-align

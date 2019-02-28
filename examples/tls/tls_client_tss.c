/* tls_client_tss.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/ssl.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_WOLFSSL_CLIENT) && \
    (defined(WOLF_CRYPTO_DEV) || defined(WOLF_CRYPTO_CB))

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#elif defined(WOLF_CRYPTO_DEV)
    #include <wolfssl/wolfcrypt/cryptodev.h>
#endif

#undef  USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_2048
#undef  USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_256
#include <wolfssl/certs_test.h>

#include "tls_common.h"
#include "tls_client.h"

#ifdef TLS_BENCH_MODE
    double benchStart;
#endif

#if 0
#include <tss2/tss2_esys.h>
#endif

/*
 * This example client connects to localhost on on port 11111 by default.
 * These can be overriden using `TLS_HOST` and `TLS_PORT`.
 *
 * You can validate using the wolfSSL example server this like:
 *   ./examples/server/server -b -p 11111 -g
 *
 * If using an ECDSA cipher suite add:
 * "-l ECDHE-ECDSA-AES128-SHA -c ./certs/server-ecc.pem -k ./certs/ecc-key.pem"
 */

typedef struct TlsTssCtx {
    void* test;
} TlsTssCtx;

static int wolfCryptoCallback(int devId, wc_CryptoInfo* info, void* ctx)
{
    int rc = NOT_COMPILED_IN; /* return this to bypass HW and use SW */
    TlsTssCtx* tlsTssCtx = (TlsTssCtx*)ctx;

    if (info == NULL || ctx == NULL)
        return BAD_FUNC_ARG;

    (void)devId;
    (void)tlsTssCtx;

    if (info->algo_type == WC_ALGO_TYPE_RNG) {
    #ifndef WC_NO_RNG
    #ifdef DEBUG_WOLFTPM
        printf("CryptoDevCb RNG: Sz %d\n", info->rng.sz);
    #endif

    #endif /* !WC_NO_RNG */
    }
#if !defined(NO_RSA) || defined(HAVE_ECC)
    else if (info->algo_type == WC_ALGO_TYPE_PK) {
    #ifdef DEBUG_WOLFTPM
        printf("CryptoDevCb Pk: Type %d\n", info->pk.type);
    #endif

    #ifndef NO_RSA
        /* RSA */
        if (info->pk.type == WC_PK_TYPE_RSA_KEYGEN) {
            rc = NOT_COMPILED_IN;
        }
        else if (info->pk.type == WC_PK_TYPE_RSA) {
            switch (info->pk.rsa.type) {
                case RSA_PUBLIC_ENCRYPT:
                case RSA_PUBLIC_DECRYPT:
                {

                    break;
                }
                case RSA_PRIVATE_ENCRYPT:
                case RSA_PRIVATE_DECRYPT:
                {

                    break;
                }
            }
        }
    #endif /* !NO_RSA */
    #ifdef HAVE_ECC
        if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {

        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {

        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {

        }
        else if (info->pk.type == WC_PK_TYPE_ECDH) {

        }
    #endif /* HAVE_ECC */
    }
#endif /* !NO_RSA || HAVE_ECC */
#ifndef NO_AES
    else if (info->algo_type == WC_ALGO_TYPE_CIPHER) {
    #ifdef DEBUG_WOLFTPM
        printf("CryptoDevCb Cipher: Type %d\n", info->cipher.type);
    #endif
        if (info->cipher.type != WC_CIPHER_AES_CBC) {
            return NOT_COMPILED_IN;
        }
    }
#endif /* !NO_AES */
#if !defined(NO_SHA) || !defined(NO_SHA256)
    else if (info->algo_type == WC_ALGO_TYPE_HASH) {
    #ifdef DEBUG_WOLFTPM
        printf("CryptoDevCb Hash: Type %d\n", info->hash.type);
    #endif
        if (info->hash.type != WC_HASH_TYPE_SHA &&
            info->hash.type != WC_HASH_TYPE_SHA256) {
            return NOT_COMPILED_IN;
        }
    }
#endif /* !NO_SHA || !NO_SHA256 */
#ifndef NO_HMAC
    else if (info->algo_type == WC_ALGO_TYPE_HMAC) {
    #ifdef DEBUG_WOLFTPM
        printf("CryptoDevCb HMAC: Type %d\n", info->hmac.macType);
    #endif
    }
#endif /* !NO_HMAC */

    /* need to return negative here for error */
    if (rc != 0 && rc != NOT_COMPILED_IN) {
    #ifdef DEBUG_WOLFTPM
        printf("wolfCryptoCallback failed rc = %d\n", rc);
    #endif
        rc = WC_HW_E;
    }

    return rc;
}


/******************************************************************************/
/* --- BEGIN TLS Client Example -- */
/******************************************************************************/
int TLS_Client_TSS(void)
{
    int rc = 0;
    SockIoCbCtx sockIoCtx;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
#ifndef TLS_BENCH_MODE
    const char webServerMsg[] = "GET /index.html HTTP/1.0\r\n\r\n";
#endif
    char msg[MAX_MSG_SZ];
    int msgSz = 0;
#ifdef TLS_BENCH_MODE
    int total_size;
    int i;
#endif
    TlsTssCtx tlsTssCtx;
    const int devId = 0x545353; /* TSS - can be anything, just not -2 (INVALID_DEVID) */

    /* initialize variables */
    XMEMSET(&sockIoCtx, 0, sizeof(sockIoCtx));
    sockIoCtx.fd = -1;

    printf("TLS Client Example\n");

    wolfSSL_Debugging_ON();

    wolfSSL_Init();

    /* Register a crypto callback */
    XMEMSET(&tlsTssCtx, 0, sizeof(tlsTssCtx));
    rc = wc_CryptoDev_RegisterDevice(devId, wolfCryptoCallback, &tlsTssCtx);
    if (rc != 0) goto exit;

    /* Setup the WOLFSSL context (factory) */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        rc = MEMORY_E; goto exit;
    }

    /* Setup IO Callbacks */
    wolfSSL_CTX_SetIORecv(ctx, SockIORecv);
    wolfSSL_CTX_SetIOSend(ctx, SockIOSend);

    /* Server certificate validation */
#if 0
    /* skip server cert validation for this test */
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, myVerify);
#else
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, myVerify);

    /* Load CA Certificates from Buffer */
    #if !defined(NO_RSA) && !defined(TLS_USE_ECC)
        if (wolfSSL_CTX_load_verify_buffer(ctx,
                ca_cert_der_2048, sizeof_ca_cert_der_2048,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            printf("Error loading ca_cert_der_2048 DER cert\n");
            goto exit;
        }
    #elif defined(HAVE_ECC)
        if (wolfSSL_CTX_load_verify_buffer(ctx,
                ca_ecc_cert_der_256, sizeof_ca_ecc_cert_der_256,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            printf("Error loading ca_ecc_cert_der_256 DER cert\n");
            goto exit;
        }
    #endif
#endif

#ifndef NO_TLS_MUTUAL_AUTH
    /* Client Certificate and Key using buffer */
    #if !defined(NO_RSA) && !defined(TLS_USE_ECC)
        if (wolfSSL_CTX_use_certificate_buffer(ctx,
                client_cert_der_2048, sizeof_client_cert_der_2048,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            goto exit;
        }
        if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                client_key_der_2048, sizeof_client_key_der_2048,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            goto exit;
        }
    #elif defined(HAVE_ECC)
        if (wolfSSL_CTX_use_certificate_buffer(ctx,
                cliecc_cert_der_256, sizeof_cliecc_cert_der_256,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            goto exit;
        }
        if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                ecc_clikey_der_256, sizeof_ecc_clikey_der_256,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            goto exit;
        }
    #endif
#endif /* !NO_TLS_MUTUAL_AUTH */

#ifdef TLS_CIPHER_SUITE
    /* Optionally choose the cipher suite */
    rc = wolfSSL_CTX_set_cipher_list(ctx, TLS_CIPHER_SUITE);
    if (rc != WOLFSSL_SUCCESS) {
        goto exit;
    }
#endif

    /* Create wolfSSL object/session */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        rc = wolfSSL_get_error(ssl, 0);
        goto exit;
    }

    /* Setup socket and connection */
    rc = SetupSocketAndConnect(&sockIoCtx, TLS_HOST, TLS_PORT);
    if (rc != 0) goto exit;

    /* Setup read/write callback contexts */
    wolfSSL_SetIOReadCtx(ssl, &sockIoCtx);
    wolfSSL_SetIOWriteCtx(ssl, &sockIoCtx);

    /* perform connect */
#ifdef TLS_BENCH_MODE
    benchStart = gettime_secs(1);
#endif
    do {
        rc = wolfSSL_connect(ssl);
        if (rc != WOLFSSL_SUCCESS) {
            rc = wolfSSL_get_error(ssl, 0);
        }
    } while (rc == WOLFSSL_ERROR_WANT_READ || rc == WOLFSSL_ERROR_WANT_WRITE);
    if (rc != WOLFSSL_SUCCESS) {
        goto exit;
    }
#ifdef TLS_BENCH_MODE
    benchStart = gettime_secs(0) - benchStart;
    printf("Connect: %9.3f sec (%9.3f CPS)\n", benchStart, 1/benchStart);
#endif

    printf("Cipher Suite: %s\n", wolfSSL_get_cipher(ssl));

#ifdef TLS_BENCH_MODE
    rc = 0;
    total_size = 0;
    while (rc == 0 && total_size < TOTAL_MSG_SZ)
#endif
    {
        /* initialize write */
    #ifdef TLS_BENCH_MODE
        msgSz = sizeof(msg); /* sequence */
        for (i=0; i<msgSz; i++) {
            msg[i] = (i & 0xff);
        }
        total_size += msgSz;
    #else
        msgSz = sizeof(webServerMsg);
        XMEMCPY(msg, webServerMsg, msgSz);
    #endif

        /* perform write */
    #ifdef TLS_BENCH_MODE
        benchStart = gettime_secs(1);
    #endif
        do {
            rc = wolfSSL_write(ssl, msg, msgSz);
            if (rc != msgSz) {
                rc = wolfSSL_get_error(ssl, 0);
            }
        } while (rc == WOLFSSL_ERROR_WANT_WRITE);
        if (rc >= 0) {
            msgSz = rc;
        #ifdef TLS_BENCH_MODE
            benchStart = gettime_secs(0) - benchStart;
            printf("Write: %d bytes in %9.3f sec (%9.3f KB/sec)\n",
                msgSz, benchStart, msgSz / benchStart / 1024);
        #else
            printf("Write (%d): %s\n", msgSz, msg);
        #endif
            rc = 0; /* success */
        }
        if (rc != 0) goto exit;

        /* perform read */
    #ifdef TLS_BENCH_MODE
        benchStart = 0; /* use the read callback to trigger timing */
    #endif
        do {
            /* attempt to fill msg buffer */
            rc = wolfSSL_read(ssl, msg, sizeof(msg));
            if (rc < 0) {
                rc = wolfSSL_get_error(ssl, 0);
            }
        } while (rc == WOLFSSL_ERROR_WANT_READ);
        if (rc >= 0) {
            msgSz = rc;
        #ifdef TLS_BENCH_MODE
            benchStart = gettime_secs(0) - benchStart;
            printf("Read: %d bytes in %9.3f sec (%9.3f KB/sec)\n",
                msgSz, benchStart, msgSz / benchStart / 1024);
        #else
            /* null terminate */
            if (msgSz >= (int)sizeof(msg))
                msgSz = (int)sizeof(msg) - 1;
            msg[msgSz] = '\0';
            printf("Read (%d): %s\n", msgSz, msg);
        #endif
            rc = 0; /* success */
        }
    }

exit:

    if (rc != 0) {
        printf("Failure %d (0x%x): %s\n", rc, rc,
            wolfSSL_ERR_reason_error_string(rc));
    }

    wolfSSL_shutdown(ssl);

    CloseAndCleanupSocket(&sockIoCtx);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    wc_CryptoCb_UnRegisterDevice(devId); /* also done on wolfSSL_Init() */
    wolfSSL_Cleanup();

    return rc;
}

/******************************************************************************/
/* --- END TLS Client Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT && !NO_WOLFSSL_CLIENT
            && WOLF_CRYPTO_CB */


#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    !defined(NO_WOLFSSL_CLIENT) && \
    (defined(WOLF_CRYPTO_DEV) || defined(WOLF_CRYPTO_CB))
    rc = TLS_Client_TSS();
#else
    printf("WolfSSL Client TSS code not compiled in\n");
    printf("Requires wolfSSL built with: ./configure --enable-cryptodev\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */

/* wolf_tss.h
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

#ifndef __WOLF_TSS_H__
#define __WOLF_TSS_H__

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

#define WOLFTSS_HASH_ALG TPM2_ALG_SHA256

typedef void* dl_handle_t;
typedef struct {
    dl_handle_t     dlhandle;
    ESYS_CONTEXT    *ectx;
} ESYS_AUXCONTEXT;

typedef enum {
    KEY_TYPE_BLOB,
    KEY_TYPE_HANDLE
} WOLFTSS_KEY_TYPE;

typedef struct {
    int emptyAuth;
    TPM2B_DIGEST userauth;
    TPM2B_PUBLIC pub;
    TPM2_HANDLE parent;
    WOLFTSS_KEY_TYPE privatetype;
    union {
      TPM2B_PRIVATE priv;
      TPM2_HANDLE handle;
    };
} WOLFTSS_DATA;


int wolftss_init(ESYS_AUXCONTEXT *pEactx, TPM2_HANDLE parentHandle,
    ESYS_TR *parent);
int wolftss_tpmpubkey_to_wolfrsakey(TPM2B_PUBLIC* tpmPubKey, RsaKey* wolfKey);

int wolftss_rsa_genkey(RsaKey *rsa, WOLFTSS_DATA** ptpm2Data,
    int bits, long e, char *password, TPM2_HANDLE parentHandle);


#endif /* __WOLF_TSS_H__ */

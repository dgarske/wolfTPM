/* wolf_tss.c
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


#include "wolf_tss.h"

static TPM2B_DIGEST kOwnerAuth = { .size = 0 };

static const TPM2B_DATA kAllOutsideInfo = {
    .size = 0,
};

static const TPML_PCR_SELECTION kAllCreationPCR = {
    .count = 0,
};

static const TPM2B_PUBLIC kRsaKeyTemplate = {
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = WOLFTSS_HASH_ALG,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_SIGN_ENCRYPT |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |
                             TPMA_OBJECT_NODA),
        .authPolicy.size = 0,
        .parameters.rsaDetail = {
             .symmetric = {
                 .algorithm = TPM2_ALG_NULL,
                 .keyBits.aes = 0,
                 .mode.aes = 0,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .keyBits = 0,          /* to be set by the genkey function */
             .exponent = 0,         /* to be set by the genkey function */
         },
        .unique.rsa.size = 0
     }
};

static const TPM2B_PUBLIC kPrimaryTemplate = {
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = WOLFTSS_HASH_ALG,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_RESTRICTED |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_NODA |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN),
        .authPolicy = {
             .size = 0,
         },
        .parameters.eccDetail = {
             .symmetric = {
                 .algorithm = TPM2_ALG_AES,
                 .keyBits.aes = 128,
                 .mode.aes = TPM2_ALG_CFB,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .curveID = TPM2_ECC_NIST_P256,
             .kdf = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
         },
        .unique.ecc = {
             .x.size = 0,
             .y.size = 0
         }
     }
};
static const TPM2B_SENSITIVE_CREATE kPrimarySensitive = {
    .sensitive = {
        .userAuth = {
             .size = 0,
         },
        .data = {
             .size = 0,
         }
    }
};

int wolftss_init(ESYS_AUXCONTEXT *pEactx, TPM2_HANDLE parentHandle,
    ESYS_TR *parent)
{
    TSS2_RC rc;

    *parent = ESYS_TR_NONE;
    pEactx->dlhandle = NULL;
    pEactx->ectx = NULL;

    rc = esys_auxctx_init(pEactx);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    if (parentHandle && parentHandle != TPM2_RH_OWNER) {
        printf("Connecting to a persistent parent key.\n");

        rc = Esys_TR_FromTPMPublic(pEactx->ectx, parentHandle,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  parent);
        if (rc != TSS2_RC_SUCCESS)
            goto error;

        return TSS2_RC_SUCCESS;
    }

    printf("Creating primary key under owner.\n");

    rc = Esys_TR_SetAuth(pEactx->ectx, ESYS_TR_RH_OWNER, &kOwnerAuth);
    if (rc != TSS2_RC_SUCCESS) {
        goto error;
    }

    rc = Esys_CreatePrimary(pEactx->ectx, ESYS_TR_RH_OWNER,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &kPrimarySensitive, &kPrimaryTemplate, &kAllOutsideInfo,
                           &kAllCreationPCR, parent, NULL, NULL, NULL, NULL);
    if (rc == 0x000009a2) {
        rc = -1; /* own auth failed */
        goto error;
    }

    if (rc == TSS2_RC_SUCCESS) {
        return rc;
    }

 error:
    if (*parent != ESYS_TR_NONE)
        Esys_FlushContext(pEactx->ectx, *parent);
    *parent = ESYS_TR_NONE;

    esys_auxctx_free(pEactx);
    return rc;
}


int wolftss_tpmpubkey_to_wolfrsakey(TPM2B_PUBLIC* tpmPubKey, RsaKey* wolfKey)
{
    int rc;
    word32  exponent;
    byte    e[sizeof(exponent)];
    byte    n[2048 / 8];
    word32  eSz = sizeof(e);
    word32  nSz = sizeof(n);

    if (tpmPubKey == NULL || wolfKey == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(e, 0, sizeof(e));
    XMEMSET(n, 0, sizeof(n));

    /* load exponent */
    exponent = tpmPubKey->publicArea.parameters.rsaDetail.exponent;
    if (exponent == 0)
        exponent = 0x00010001;
    e[3] = (exponent >> 24) & 0xFF;
    e[2] = (exponent >> 16) & 0xFF;
    e[1] = (exponent >> 8)  & 0xFF;
    e[0] =  exponent        & 0xFF;
    eSz = e[3] ? 4 : e[2] ? 3 : e[1] ? 2 : e[0] ? 1 : 0; /* calc size */

    /* load public key */
    nSz = tpmPubKey->publicArea.unique.rsa.size;
    XMEMCPY(n, tpmPubKey->publicArea.unique.rsa.buffer, nSz);

    /* load public key portion into wolf RsaKey */
    rc = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, wolfKey);

    return rc;
}

int wolftss_rsa_genkey(RsaKey *rsa, WOLFTSS_DATA** ptpm2Data,
    int bits, long e, char *password, TPM2_HANDLE parentHandle)
{
    TSS2_RC rc = TSS2_RC_SUCCESS;
    ESYS_AUXCONTEXT eactx = { NULL, NULL };
    ESYS_TR parent = ESYS_TR_NONE;
    TPM2B_PUBLIC *keyPublic = NULL;
    TPM2B_PRIVATE *keyPrivate = NULL;
    TPM2B_PUBLIC inPublic = kRsaKeyTemplate;
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .sensitive = {
            .userAuth = {
                 .size = 0,
             },
            .data = {
                 .size = 0,
             }
        }
    };
    WOLFTSS_DATA* tpm2Data = NULL;

    if (ptpm2Data == NULL || rsa == NULL) {
        return BAD_FUNC_ARG;
    }

    printf("Generating RSA key for %i bits keysize.\n", bits);

    tpm2Data = malloc(sizeof(WOLFTSS_DATA));
    if (tpm2Data == NULL) {
        rc = MEMORY_E;
        goto error;
    }
    memset(tpm2Data, 0, sizeof(WOLFTSS_DATA));

    inPublic.publicArea.parameters.rsaDetail.keyBits = bits;
    inPublic.publicArea.parameters.rsaDetail.exponent = e;

    if (password) {
        printf("Setting a password for the created key.\n");
        if (strlen(password) > sizeof(tpm2Data->userauth.buffer) - 1) {
            goto error;
        }
        tpm2Data->userauth.size = strlen(password);
        memcpy(&tpm2Data->userauth.buffer[0], password,
               tpm2Data->userauth.size);

        inSensitive.sensitive.userAuth.size = strlen(password);
        memcpy(&inSensitive.sensitive.userAuth.buffer[0], password,
               strlen(password));
    }
    else {
        tpm2Data->emptyAuth = 1;
    }

    rc = wolftss_init(&eactx, parentHandle, &parent);
    if (rc != 0)
        goto err;

    tpm2Data->parent = parentHandle;

    printf("Generating the RSA key inside the TPM.\n");

    rc = Esys_Create(eactx.ectx, parent,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive, &inPublic, &kAllOutsideInfo, &kAllCreationPCR,
                    &keyPrivate, &keyPublic, NULL, NULL, NULL);
    if (rc != 0)
        goto error;

    tpm2Data->pub = *keyPublic;
    tpm2Data->priv = *keyPrivate;

    /* load TPM public into RsaKey */
    rc = wolftss_tpmpubkey_to_wolfrsakey(keyPublic, rsa);

    if (rc == 0)
        goto end;

 error:

    if (tpm2Data)
        free(tpm2Data);

 end:
    free(keyPrivate);
    free(keyPublic);

    if (parent != ESYS_TR_NONE && !parentHandle)
        Esys_FlushContext(eactx.ectx, parent);

    esys_auxctx_free(&eactx);

    if (ptpm2Data)
        *ptpm2Data = tpm2Data;

    return rc;
}


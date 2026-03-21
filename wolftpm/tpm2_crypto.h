/* tpm2_crypto.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef _TPM2_CRYPTO_H_
#define _TPM2_CRYPTO_H_

#include <wolftpm/tpm2.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* --- KDF Functions (moved from tpm2_param_enc.h) --- */

/* KDFa - HMAC-based Key Derivation Function
 * Per TPM 2.0 spec Part 1 Section 11.4.10.2
 * Returns number of bytes generated (keySz) on success, or negative on error.
 */
WOLFTPM_API int TPM2_KDFa(
    TPM_ALG_ID hashAlg,
    const BYTE *keyIn, UINT32 keyInSz,
    const char *label,
    const BYTE *contextU, UINT32 contextUSz,
    const BYTE *contextV, UINT32 contextVSz,
    BYTE *key, UINT32 keySz
);

/* KDFe - Hash-based Key Derivation Function (for ECDH salt, etc.)
 * Per TPM 2.0 spec Part 1 Section 11.4.10.3
 * Returns number of bytes generated (keySz) on success, or negative on error.
 */
WOLFTPM_API int TPM2_KDFe(
    TPM_ALG_ID hashAlg,
    const BYTE *Z, UINT32 ZSz,
    const char *label,
    const BYTE *partyU, UINT32 partyUSz,
    const BYTE *partyV, UINT32 partyVSz,
    BYTE *key, UINT32 keySz
);

/* --- Crypto Primitive Wrappers --- */

/* AES-CFB one-shot encrypt (in-place).
 * iv may be NULL for zero IV. Returns 0 on success. */
WOLFTPM_API int TPM2_AesCfbEncrypt(
    const byte* key, int keySz,
    const byte* iv,
    byte* data, word32 dataSz);

/* AES-CFB one-shot decrypt (in-place).
 * iv may be NULL for zero IV. Returns 0 on success. */
WOLFTPM_API int TPM2_AesCfbDecrypt(
    const byte* key, int keySz,
    const byte* iv,
    byte* data, word32 dataSz);

/* HMAC one-shot compute.
 * data2/data2Sz are optional (pass NULL/0 to skip).
 * On input *digestSz is buffer size; on output actual digest size.
 * Returns 0 on success. */
WOLFTPM_API int TPM2_HmacCompute(
    TPMI_ALG_HASH hashAlg,
    const byte* key, word32 keySz,
    const byte* data, word32 dataSz,
    const byte* data2, word32 data2Sz,
    byte* digest, word32* digestSz);

/* HMAC verify (compute + constant-time compare).
 * data2/data2Sz are optional (pass NULL/0 to skip).
 * Returns 0 on match, TPM_RC_INTEGRITY on mismatch. */
WOLFTPM_API int TPM2_HmacVerify(
    TPMI_ALG_HASH hashAlg,
    const byte* key, word32 keySz,
    const byte* data, word32 dataSz,
    const byte* data2, word32 data2Sz,
    const byte* expected, word32 expectedSz);

/* Hash one-shot compute.
 * On input *digestSz is buffer size; on output actual digest size.
 * Returns 0 on success. */
WOLFTPM_API int TPM2_HashCompute(
    TPMI_ALG_HASH hashAlg,
    const byte* data, word32 dataSz,
    byte* digest, word32* digestSz);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _TPM2_CRYPTO_H_ */

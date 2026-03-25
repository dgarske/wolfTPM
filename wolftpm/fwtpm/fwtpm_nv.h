/* fwtpm_nv.h
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

#ifndef _FWTPM_NV_H_
#define _FWTPM_NV_H_

#ifdef WOLFTPM_FWTPM

#include <wolftpm/fwtpm/fwtpm.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* NV storage file path */
#ifndef FWTPM_NV_FILE
#define FWTPM_NV_FILE "fwtpm_nv.bin"
#endif

/* NV file header magic and version */
#define FWTPM_NV_MAGIC     0x66775450  /* "fwTP" */
#define FWTPM_NV_VERSION   3           /* TLV journal format */

/* Hierarchy seed size (SHA-384 digest length) */
#define FWTPM_SEED_SIZE    TPM_SHA384_DIGEST_SIZE

/* Maximum NV region size (default 128 KB) */
#ifndef FWTPM_NV_MAX_SIZE
#define FWTPM_NV_MAX_SIZE  (128 * 1024)
#endif

/* Maximum single TLV entry value size (PCR state is largest) */
#define FWTPM_NV_MAX_ENTRY (IMPLEMENTATION_PCR * FWTPM_PCR_BANKS * \
                            TPM_MAX_DIGEST_SIZE + 4)

/* NV HAL type alias - struct defined in fwtpm.h as part of FWTPM_CTX */
typedef struct FWTPM_NV_HAL_S FWTPM_NV_HAL;

/* NV file header (stored at start of NV image) */
typedef struct FWTPM_NV_HEADER {
    UINT32 magic;
    UINT32 version;
    UINT32 writePos;    /* Current write position (next append offset) */
    UINT32 maxSize;     /* Total NV region size */
} FWTPM_NV_HEADER;

/* --- TLV Tag definitions ---
 * Each NV entry is: [UINT16 tag][UINT16 length][byte value[length]]
 * Tags 0x0000 = invalid/deleted, 0xFFFF = free space (erased flash).
 * For multi-instance tags (NV index, persistent, cache), the value
 * starts with a UINT32 handle for identification. */

#define FWTPM_NV_TAG_FREE              0xFFFF  /* Erased flash */
#define FWTPM_NV_TAG_INVALID           0x0000  /* Sentinel/deleted */

/* Hierarchy seeds (48 bytes each) */
#define FWTPM_NV_TAG_OWNER_SEED        0x0001
#define FWTPM_NV_TAG_ENDORSEMENT_SEED  0x0002
#define FWTPM_NV_TAG_PLATFORM_SEED     0x0003

/* Hierarchy auth values (variable: 0-48 bytes) */
#define FWTPM_NV_TAG_OWNER_AUTH        0x0010
#define FWTPM_NV_TAG_ENDORSEMENT_AUTH  0x0011
#define FWTPM_NV_TAG_PLATFORM_AUTH     0x0012
#define FWTPM_NV_TAG_LOCKOUT_AUTH      0x0013

/* PCR state (all banks + counter) */
#define FWTPM_NV_TAG_PCR_STATE         0x0020
#define FWTPM_NV_TAG_PCR_AUTH          0x0025  /* Per-PCR auth/policy state */

/* Flags (disableClear, DA params, etc.) */
#define FWTPM_NV_TAG_FLAGS             0x0030

/* Hierarchy policies (value: UINT32 hierarchy + UINT16 alg + digest) */
#define FWTPM_NV_TAG_HIERARCHY_POLICY  0x0035

/* Clock offset (value: UINT64 clockOffset, survives reboot) */
#define FWTPM_NV_TAG_CLOCK             0x0038

/* NV indices (value starts with UINT32 nvHandle) */
#define FWTPM_NV_TAG_NV_INDEX          0x0040
#define FWTPM_NV_TAG_NV_INDEX_DEL      0x0041

/* Persistent objects (value starts with UINT32 handle) */
#define FWTPM_NV_TAG_PERSISTENT        0x0050
#define FWTPM_NV_TAG_PERSISTENT_DEL    0x0051

/* Primary cache (value: UINT32 hierarchy + byte[32] templateHash + ...) */
#define FWTPM_NV_TAG_PRIMARY_CACHE     0x0060
#define FWTPM_NV_TAG_PRIMARY_CACHE_DEL 0x0061

/* --- Public API --- */

/** \brief Initialize NV subsystem. Loads existing journal or creates new. */
WOLFTPM_API int FWTPM_NV_Init(FWTPM_CTX* ctx);

/** \brief Save all state — compact journal and write full state. */
WOLFTPM_API int FWTPM_NV_Save(FWTPM_CTX* ctx);

/** \brief Set NV HAL callbacks (optional - defaults to file-based). */
WOLFTPM_API int FWTPM_NV_SetHAL(FWTPM_CTX* ctx, FWTPM_NV_HAL* hal);

/* --- Targeted saves — append single entry to journal --- */

/** \brief Save hierarchy seeds to NV journal. */
WOLFTPM_API int FWTPM_NV_SaveSeeds(FWTPM_CTX* ctx);

/** \brief Save a single hierarchy auth value to NV journal. */
WOLFTPM_API int FWTPM_NV_SaveAuth(FWTPM_CTX* ctx, UINT32 hierarchy);

/** \brief Save PCR state to NV journal. */
WOLFTPM_API int FWTPM_NV_SavePcrState(FWTPM_CTX* ctx);

/** \brief Save per-PCR auth/policy state to NV journal. */
WOLFTPM_API int FWTPM_NV_SavePcrAuth(FWTPM_CTX* ctx);

/** \brief Save flags (disableClear, DA params) to NV journal. */
WOLFTPM_API int FWTPM_NV_SaveFlags(FWTPM_CTX* ctx);

/** \brief Save clock offset to NV journal. */
WOLFTPM_API int FWTPM_NV_SaveClock(FWTPM_CTX* ctx);

/** \brief Save a hierarchy policy to NV journal. */
WOLFTPM_API int FWTPM_NV_SaveHierarchyPolicy(FWTPM_CTX* ctx,
    UINT32 hierarchy);

/** \brief Save an NV index to NV journal. */
WOLFTPM_API int FWTPM_NV_SaveNvIndex(FWTPM_CTX* ctx, int slot);

/** \brief Delete an NV index from NV journal. */
WOLFTPM_API int FWTPM_NV_DeleteNvIndex(FWTPM_CTX* ctx, UINT32 nvHandle);

/** \brief Save a persistent object to NV journal. */
WOLFTPM_API int FWTPM_NV_SavePersistent(FWTPM_CTX* ctx, int slot);

/** \brief Delete a persistent object from NV journal. */
WOLFTPM_API int FWTPM_NV_DeletePersistent(FWTPM_CTX* ctx, UINT32 handle);

/** \brief Save a primary cache entry to NV journal. */
WOLFTPM_API int FWTPM_NV_SavePrimaryCache(FWTPM_CTX* ctx, int slot);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFTPM_FWTPM */

#endif /* _FWTPM_NV_H_ */

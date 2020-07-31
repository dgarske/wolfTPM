/* seal.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

/* This example shows how to use extended authorization sessions (TPM2.0) and
 * generate a signed timestamp from the TPM using a Attestation Identity Key.
 */

#include <wolftpm/tpm2_wrap.h>

#include <examples/seal/seal.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>

/******************************************************************************/
/* --- BEGIN TPM Seal Test -- */
/******************************************************************************/

int TPM2_Seal_Test(void* userCtx)
{
    int rc = NOT_COMPILED_IN;

    /* A random, TPM-generated, Sealed Data Object may be created by the TPM with 
     * TPM2_Create() or TPM2_CreatePrimary() using the template for a Sealed Data Object.
     */

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }
    (void)userCtx;
    return rc;
}

/******************************************************************************/
/* --- END TPM Seal Test -- */
/******************************************************************************/

#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc;

    rc = TPM2_Seal_Test(NULL);

    return rc;
}
#endif

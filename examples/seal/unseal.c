/* unseal.c
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

#include <examples/seal/unseal.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>

/******************************************************************************/
/* --- BEGIN TPM Unseal Test -- */
/******************************************************************************/

int TPM2_Unseal_Test(void* userCtx)
{
    int rc = NOT_COMPILED_IN;
    Unseal_In in;
    Unseal_Out out;

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));

    //in.itemHandle = handle;
    rc = TPM2_Unseal(&in, &out);

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }
    (void)userCtx;
    return rc;
}

/******************************************************************************/
/* --- END TPM Unseal Test -- */
/******************************************************************************/

#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc;

    rc = TPM2_Unseal_Test(NULL);

    return rc;
}
#endif

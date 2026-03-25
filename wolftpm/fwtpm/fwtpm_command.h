/* fwtpm_command.h
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

#ifndef _FWTPM_COMMAND_H_
#define _FWTPM_COMMAND_H_

#ifdef WOLFTPM_FWTPM

#include <wolftpm/fwtpm/fwtpm.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Process a TPM command buffer and produce a response buffer.
 * cmdBuf/cmdSize: input command (big-endian TPM packet)
 * rspBuf/rspSize: output response buffer and resulting size
 * locality: the locality from the transport layer
 * Returns TPM_RC_SUCCESS on successful processing (response may contain error RC)
 */
WOLFTPM_API int FWTPM_ProcessCommand(FWTPM_CTX* ctx,
    const byte* cmdBuf, int cmdSize,
    byte* rspBuf, int* rspSize, int locality);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFTPM_FWTPM */

#endif /* _FWTPM_COMMAND_H_ */

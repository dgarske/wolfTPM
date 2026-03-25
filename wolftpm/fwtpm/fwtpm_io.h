/* fwtpm_io.h
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

#ifndef _FWTPM_IO_H_
#define _FWTPM_IO_H_

#ifdef WOLFTPM_FWTPM

#include <wolftpm/fwtpm/fwtpm.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* SWTPM TCP protocol commands (from TpmTcpProtocol.h) */
#define FWTPM_TCP_SIGNAL_POWER_ON       1
#define FWTPM_TCP_SIGNAL_POWER_OFF      2
#define FWTPM_TCP_SIGNAL_PHYS_PRES_ON   3
#define FWTPM_TCP_SIGNAL_PHYS_PRES_OFF  4
#define FWTPM_TCP_SIGNAL_HASH_START     5
#define FWTPM_TCP_SIGNAL_HASH_DATA      6
#define FWTPM_TCP_SIGNAL_HASH_END       9
#define FWTPM_TCP_SEND_COMMAND          8
#define FWTPM_TCP_SIGNAL_NV_ON         11
#define FWTPM_TCP_SIGNAL_CANCEL_ON     13
#define FWTPM_TCP_SIGNAL_CANCEL_OFF    14
#define FWTPM_TCP_SIGNAL_RESET         17
#define FWTPM_TCP_SESSION_END          20
#define FWTPM_TCP_STOP                 21

/* FWTPM_IO_CTX is defined in fwtpm.h (included above) */

#ifndef WOLFTPM_FWTPM_TIS
/* Set IO HAL callbacks (optional - socket transport only) */
WOLFTPM_API int FWTPM_IO_SetHAL(FWTPM_CTX* ctx, FWTPM_IO_HAL* hal);
#endif

/* Initialize transport (sockets by default, or custom HAL) */
WOLFTPM_API int FWTPM_IO_Init(FWTPM_CTX* ctx);

/* Cleanup sockets */
WOLFTPM_API void FWTPM_IO_Cleanup(FWTPM_CTX* ctx);

/* Main server loop - blocks until ctx->running is cleared */
WOLFTPM_API int FWTPM_IO_ServerLoop(FWTPM_CTX* ctx);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFTPM_FWTPM */

#endif /* _FWTPM_IO_H_ */

/* tls_server.h
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

#ifndef _TPM_TLS_SERVER_H_
#define _TPM_TLS_SERVER_H_

#ifdef __cplusplus
    extern "C" {
#endif

int TPM2_TLS_Server(void* userCtx);
int TPM2_TLS_ServerArgs(void* userCtx, int argc, char* argv[]);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _TPM_TLS_SERVER_H_ */

# fwTPM Embedded Ports

Platform-specific ports of the wolfTPM fwTPM server for embedded targets.

## Available Ports

| Port | Directory | Description |
|------|-----------|-------------|
| STM32 | [stm32/](stm32/) | STM32 Cortex-M with TrustZone (CMSE) |

## Porting Guide

To add a new platform, implement these HAL callbacks:

1. **NV Storage HAL** (`FWTPM_NV_HAL`): `read()`, `write()`, `erase()` for
   persistent flash storage. Register via `FWTPM_NV_SetHAL()` before `FWTPM_Init()`.

2. **Clock HAL** (optional): `get_ms()` returning milliseconds since boot.
   Register via `FWTPM_Clock_SetHAL()` before `FWTPM_Init()`.

3. **Entry point**: Zero `FWTPM_CTX`, register HALs, call `FWTPM_Init()`,
   then process TPM commands via `FWTPM_ProcessCommand()`.

See `stm32/` for a complete reference implementation.

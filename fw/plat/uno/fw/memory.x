/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

MEMORY
{
    FLASH : ORIGIN = 0x00000000, LENGTH = 512K
    /* DTCM — CPU-only, holds stack and .bss.
       Upper 67 KB reserved (see rdl/soc/dtcm_map.rdl):
         0x2002_F400  DTCM_IO_BUF[32]  (64 KB)
         0x2003_F400  CRASHDUMP_BASE   (1024 B)
         0x2003_F800  CORE_RUN_STATUS  (4 B)
       LENGTH capped at 189K. */
    RAM   : ORIGIN = 0x20000000, LENGTH = 189K
}


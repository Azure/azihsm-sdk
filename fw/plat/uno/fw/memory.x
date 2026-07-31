/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

MEMORY
{
    FLASH : ORIGIN = 0x00000000, LENGTH = 512K
    /* DTCM — CPU-only, holds stack and .bss.
       Upper region reserved (see rdl/soc/dtcm_map.rdl):
         0x2002_EC00  DTCM_IO_BUF[33]   (49.5 KB, 1.5 KB each)
         0x2003_B400  DEV_ID_CERT_BLOB  (16 KB)
         0x2003_F400  CRASHDUMP_BASE    (1024 B)
         0x2003_F800  CORE_RUN_STATUS   (4 B)
       LENGTH capped at 187K. */
    RAM   : ORIGIN = 0x20000000, LENGTH = 187K
}


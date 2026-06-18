/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

MEMORY
{
    FLASH : ORIGIN = 0x00000000, LENGTH = 512K
    /* DTCM — CPU-only, holds stack and .bss.
       The region at 0x2003_F400–0x2003_F803 is reserved for
       hsm_dtcm_status (see rdl/soc/dtcm_map.rdl):
         0x2003_F400  CRASHDUMP_BASE   (1024 B)
         0x2003_F800  CORE_RUN_STATUS  (4 B)
       LENGTH is capped at 253K to prevent the linker from placing
       .bss or stack into the reserved region. */
    RAM   : ORIGIN = 0x20000000, LENGTH = 253K
}


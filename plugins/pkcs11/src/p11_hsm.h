// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "p11_compat.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * HSM-binding layer: the only place that calls azihsm_* and the only place that
 * translates azihsm_status into CK_RV (via p11_status.h). Compiled against the
 * SDK under AZIHSM_WITH_HSM; the no-device build provides stubs so the framework
 * still loads and the object/digest paths remain testable.
 */

/*
 * Enumerate AZIHSM partitions into g_p11.slots[] and set g_p11.slot_count.
 * Returns the number of slots (>= 0), or -1 on error.
 */
int p11_hsm_enumerate_slots(void);

/*
 * Log a user into `slot`: open the partition, provision it lazily (only if the
 * device reports it is not yet provisioned — provisioning is one-shot per power
 * cycle), then open a session. On success writes the AZIHSM session handle to
 * *out_session. `pin`/`pin_len` are the C_Login PIN (see the PIN-shape mapping).
 */
CK_RV p11_hsm_login(
    CK_SLOT_ID slot,
    const CK_UTF8CHAR *pin,
    CK_ULONG pin_len,
    uint32_t *out_session
);

/* Close a previously opened AZIHSM session (no-op if 0). */
void p11_hsm_logout(uint32_t hsm_session);

/* Close every open partition handle. Called from C_Finalize. */
void p11_hsm_close_all(void);

#ifdef __cplusplus
}
#endif

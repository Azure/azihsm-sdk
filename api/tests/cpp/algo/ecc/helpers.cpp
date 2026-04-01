// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "helpers.hpp"
#include "ecc_static_der.hpp"
#include "utils/auto_key.hpp"
#include "utils/rsa_keygen.hpp"

#include <algorithm>

DefaultEccPrivKeyProps::DefaultEccPrivKeyProps()
{
    props.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
    props.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
    props.push_back({ AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve) });
    props.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) });
    props.push_back({ AZIHSM_KEY_PROP_ID_SIGN, &can_sign, sizeof(can_sign) });
}

azihsm_key_prop_list DefaultEccPrivKeyProps::get_prop_list()
{
    return { props.data(), static_cast<uint32_t>(props.size()) };
}

DefaultEccPubKeyProps::DefaultEccPubKeyProps()
{
    props.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
    props.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
    props.push_back({ AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve) });
    props.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) });
    props.push_back({ AZIHSM_KEY_PROP_ID_VERIFY, &can_verify, sizeof(can_verify) });
}

azihsm_key_prop_list DefaultEccPubKeyProps::get_prop_list()
{
    return { props.data(), static_cast<uint32_t>(props.size()) };
}

azihsm_status generate_ecc_keypair(
    azihsm_handle session,
    azihsm_ecc_curve curve,
    bool session_key,
    azihsm_handle *priv_key_handle,
    azihsm_handle *pub_key_handle
)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    uint32_t priv_key_class = AZIHSM_KEY_CLASS_PRIVATE;
    uint32_t priv_key_kind = AZIHSM_KEY_KIND_ECC;
    uint32_t priv_ecc_curve = curve;
    uint8_t session_key_flag = session_key ? 1 : 0;
    uint8_t priv_can_sign = 1;

    std::vector<azihsm_key_prop> priv_props = {
        { AZIHSM_KEY_PROP_ID_CLASS, &priv_key_class, sizeof(priv_key_class) },
        { AZIHSM_KEY_PROP_ID_KIND, &priv_key_kind, sizeof(priv_key_kind) },
        { AZIHSM_KEY_PROP_ID_EC_CURVE, &priv_ecc_curve, sizeof(priv_ecc_curve) },
        { AZIHSM_KEY_PROP_ID_SESSION, &session_key_flag, sizeof(session_key_flag) },
        { AZIHSM_KEY_PROP_ID_SIGN, &priv_can_sign, sizeof(priv_can_sign) }
    };

    azihsm_key_prop_list priv_prop_list{ priv_props.data(),
                                         static_cast<uint32_t>(priv_props.size()) };

    uint32_t pub_key_class = AZIHSM_KEY_CLASS_PUBLIC;
    uint32_t pub_key_kind = AZIHSM_KEY_KIND_ECC;
    uint32_t pub_ecc_curve = curve;
    uint8_t pub_can_verify = 1;

    std::vector<azihsm_key_prop> pub_props = {
        { AZIHSM_KEY_PROP_ID_CLASS, &pub_key_class, sizeof(pub_key_class) },
        { AZIHSM_KEY_PROP_ID_KIND, &pub_key_kind, sizeof(pub_key_kind) },
        { AZIHSM_KEY_PROP_ID_EC_CURVE, &pub_ecc_curve, sizeof(pub_ecc_curve) },
        { AZIHSM_KEY_PROP_ID_SESSION, &session_key_flag, sizeof(session_key_flag) },
        { AZIHSM_KEY_PROP_ID_VERIFY, &pub_can_verify, sizeof(pub_can_verify) }
    };

    azihsm_key_prop_list pub_prop_list{ pub_props.data(), static_cast<uint32_t>(pub_props.size()) };

    return azihsm_key_gen_pair(
        session,
        &keygen_algo,
        &priv_prop_list,
        &pub_prop_list,
        priv_key_handle,
        pub_key_handle
    );
}

// Builds a valid RSA-AES wrapped blob for ECC key_unwrap_pair tests:
// 1) Look up the precomputed PKCS#8 DER plaintext for the requested curve.
// 2) Configure RSA-AES wrap params (OAEP hash/MGF1/label + AES key size).
// 3) Call azihsm_crypt_encrypt to produce wrapped bytes.
azihsm_status make_wrapped_ecc_pkcs8_blob(
    azihsm_handle wrapping_pub_key,
    azihsm_ecc_curve curve,
    const RsaAesWrapConfig &wrap_config,
    std::vector<uint8_t> &wrapped_blob
)
{
    const uint8_t *pkcs8_der = nullptr;
    size_t pkcs8_der_len = 0;
    auto der_err = get_static_ecc_pkcs8_der(curve, pkcs8_der, pkcs8_der_len);
    if (der_err != AZIHSM_STATUS_SUCCESS)
    {
        wrapped_blob.clear();
        return der_err;
    }

    azihsm_algo_rsa_pkcs_oaep_params oaep_params{};
    oaep_params.hash_algo_id = wrap_config.hash_algo;
    oaep_params.mgf1_hash_algo_id = wrap_config.mgf1_hash_algo;
    oaep_params.label = wrap_config.label;

    azihsm_algo_rsa_aes_wrap_params wrap_params{};
    wrap_params.oaep_params = &oaep_params;
    wrap_params.aes_key_bits = wrap_config.aes_key_bits;

    azihsm_algo wrap_algo{};
    wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
    wrap_algo.params = &wrap_params;
    wrap_algo.len = sizeof(wrap_params);

    azihsm_buffer in_buf{};
    in_buf.ptr = const_cast<uint8_t *>(pkcs8_der);
    in_buf.len = static_cast<uint32_t>(pkcs8_der_len);

    // Two-pass pattern: query required wrapped size first, then create bytes.
    azihsm_buffer out_buf{};
    out_buf.ptr = nullptr;
    out_buf.len = 0;

    auto err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &in_buf, &out_buf);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL || out_buf.len == 0)
    {
        wrapped_blob.clear();
        return err;
    }

    wrapped_blob.resize(out_buf.len);
    out_buf.ptr = wrapped_blob.data();

    err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &in_buf, &out_buf);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        wrapped_blob.clear();
        return err;
    }

    wrapped_blob.resize(out_buf.len);
    return AZIHSM_STATUS_SUCCESS;
}

// Removes all entries with the given property ID from a key-property vector.
void remove_prop_by_id(std::vector<azihsm_key_prop> &props, azihsm_key_prop_id prop_id)
{
    props.erase(
        std::remove_if(
            props.begin(),
            props.end(),
            [&](const azihsm_key_prop &prop) { return prop.id == prop_id; }
        ),
        props.end()
    );
}

// Reads common ECC key identity fields used by parity checks.
azihsm_status read_ecc_key_summary(azihsm_handle key, EccKeySummary &summary)
{
    auto err = get_key_prop(key, AZIHSM_KEY_PROP_ID_KIND, summary.kind);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    return get_key_prop(key, AZIHSM_KEY_PROP_ID_EC_CURVE, summary.curve);
}

bool is_expected_ecc_curve(const EccKeySummary &summary, azihsm_ecc_curve expected_curve)
{
    return summary.kind == AZIHSM_KEY_KIND_ECC && summary.curve == expected_curve;
}

// Extracts the masked-key blob from a private key using size-probe then fetch pattern.
azihsm_status get_masked_key_blob(azihsm_handle private_key, std::vector<uint8_t> &masked_key_data)
{
    azihsm_key_prop masked_prop{};
    masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
    masked_prop.val = nullptr;
    masked_prop.len = 0;

    auto err = azihsm_key_get_prop(private_key, &masked_prop);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        return err;
    }

    masked_key_data.resize(masked_prop.len);
    masked_prop.val = masked_key_data.data();

    return azihsm_key_get_prop(private_key, &masked_prop);
}

// Generates an ECC key pair and returns a valid masked private-key blob for unmask_pair tests.
azihsm_status make_valid_masked_ecc_blob(
    azihsm_handle session,
    azihsm_ecc_curve curve,
    std::vector<uint8_t> &masked_key_data
)
{
    auto_key private_key;
    auto_key public_key;

    auto err =
        generate_ecc_keypair(session, curve, true, private_key.get_ptr(), public_key.get_ptr());
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    return get_masked_key_blob(private_key.get(), masked_key_data);
}

// Common inputs for RSA-AES unwrap tests.
RsaAesUnwrapPairInputs::RsaAesUnwrapPairInputs(uint8_t wrapped_blob_byte)
    : wrapped_blob_byte(wrapped_blob_byte)
{
    wrapped_key_buf.ptr = &this->wrapped_blob_byte;
    wrapped_key_buf.len = 1;

    oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
    oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
    oaep_params.label = nullptr;

    unwrap_params.aes_key_bits = 256;
    unwrap_params.oaep_params = &oaep_params;

    unwrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP;
    unwrap_algo.params = &unwrap_params;
    unwrap_algo.len = sizeof(unwrap_params);
}

// RSA-AES unwrap algorithm common parameter setup.
RsaAesUnwrapAlgo::RsaAesUnwrapAlgo(const RsaAesWrapConfig &wrap_config)
{
    oaep_params.hash_algo_id = wrap_config.hash_algo;
    oaep_params.mgf1_hash_algo_id = wrap_config.mgf1_hash_algo;
    oaep_params.label = wrap_config.label;

    unwrap_params.aes_key_bits = wrap_config.aes_key_bits;
    unwrap_params.oaep_params = &oaep_params;

    algo.id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP;
    algo.params = &unwrap_params;
    algo.len = sizeof(unwrap_params);
}

// Calls key_unmask_pair and returns status plus output handles for explicit test assertions.
UnmaskPairResult try_unmask_pair(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    azihsm_buffer *masked_key
)
{
    UnmaskPairResult result{};
    result.status = azihsm_key_unmask_pair(
        session,
        key_kind,
        masked_key,
        &result.private_key,
        &result.public_key
    );
    return result;
}

// Calls key_unwrap_pair and returns status plus output handles for explicit test assertions.
UnwrapPairResult try_unwrap_pair(
    azihsm_algo *algo,
    azihsm_handle unwrapping_key,
    azihsm_buffer *wrapped_key,
    azihsm_key_prop_list *priv_props,
    azihsm_key_prop_list *pub_props
)
{
    UnwrapPairResult result{};
    result.status = azihsm_key_unwrap_pair(
        algo,
        unwrapping_key,
        wrapped_key,
        priv_props,
        pub_props,
        &result.private_key,
        &result.public_key
    );
    return result;
}

// Runs an ECDSA sign/verify roundtrip and returns step-level diagnostics for easier triage.
EcdsaRoundtripResult run_ecdsa_sign_verify_roundtrip(
    azihsm_handle private_key,
    azihsm_handle public_key,
    const std::vector<uint8_t> &message
)
{
    if (message.empty())
    {
        return EcdsaRoundtripResult{ AZIHSM_STATUS_INVALID_ARGUMENT,
                                     "input_validation",
                                     "message is empty" };
    }

    azihsm_algo sign_algo = { AZIHSM_ALGO_ID_ECDSA_SHA256, nullptr, 0 };

    azihsm_buffer data_buf{};
    data_buf.ptr = const_cast<uint8_t *>(message.data());
    data_buf.len = static_cast<uint32_t>(message.size());

    azihsm_buffer sig_buf{};
    sig_buf.ptr = nullptr;
    sig_buf.len = 0;
    auto err = azihsm_crypt_sign(&sign_algo, private_key, &data_buf, &sig_buf);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        return EcdsaRoundtripResult{ err,
                                     "sign_size_probe",
                                     "expected BUFFER_TOO_SMALL from sign size probe" };
    }
    if (sig_buf.len == 0)
    {
        return EcdsaRoundtripResult{ AZIHSM_STATUS_INTERNAL_ERROR,
                                     "sign_size_probe",
                                     "signature length is zero after size probe" };
    }

    std::vector<uint8_t> signature(sig_buf.len);
    sig_buf.ptr = signature.data();
    err = azihsm_crypt_sign(&sign_algo, private_key, &data_buf, &sig_buf);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return EcdsaRoundtripResult{ err,
                                     "sign_materialize",
                                     "sign failed when materializing signature bytes" };
    }
    if (sig_buf.len == 0)
    {
        return EcdsaRoundtripResult{ AZIHSM_STATUS_INTERNAL_ERROR,
                                     "sign_materialize",
                                     "signature length is zero after sign" };
    }

    azihsm_buffer verify_sig_buf{};
    verify_sig_buf.ptr = signature.data();
    verify_sig_buf.len = sig_buf.len;
    err = azihsm_crypt_verify(&sign_algo, public_key, &data_buf, &verify_sig_buf);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return EcdsaRoundtripResult{ err,
                                     "verify_original_message",
                                     "verify failed for original message" };
    }

    std::vector<uint8_t> modified_message = message;
    modified_message[0] ^= 0xFF;
    azihsm_buffer modified_data_buf{};
    modified_data_buf.ptr = modified_message.data();
    modified_data_buf.len = static_cast<uint32_t>(modified_message.size());
    err = azihsm_crypt_verify(&sign_algo, public_key, &modified_data_buf, &verify_sig_buf);
    if (err == AZIHSM_STATUS_SUCCESS)
    {
        return EcdsaRoundtripResult{ AZIHSM_STATUS_INTERNAL_ERROR,
                                     "verify_modified_message",
                                     "verify unexpectedly succeeded for modified message" };
    }

    return EcdsaRoundtripResult{};
}

azihsm_status ecdsa_sign_sha256(
    azihsm_handle private_key,
    const std::vector<uint8_t> &message,
    std::vector<uint8_t> &signature
)
{
    if (message.empty())
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    azihsm_algo sign_algo = { AZIHSM_ALGO_ID_ECDSA_SHA256, nullptr, 0 };

    azihsm_buffer data_buf{};
    data_buf.ptr = const_cast<uint8_t *>(message.data());
    data_buf.len = static_cast<uint32_t>(message.size());

    azihsm_buffer sig_buf{};
    sig_buf.ptr = nullptr;
    sig_buf.len = 0;

    auto err = azihsm_crypt_sign(&sign_algo, private_key, &data_buf, &sig_buf);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL || sig_buf.len == 0)
    {
        return err;
    }

    signature.resize(sig_buf.len);
    sig_buf.ptr = signature.data();
    return azihsm_crypt_sign(&sign_algo, private_key, &data_buf, &sig_buf);
}

azihsm_status ecdsa_verify_sha256(
    azihsm_handle public_key,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &signature
)
{
    if (message.empty() || signature.empty())
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    azihsm_algo sign_algo = { AZIHSM_ALGO_ID_ECDSA_SHA256, nullptr, 0 };

    azihsm_buffer data_buf{};
    data_buf.ptr = const_cast<uint8_t *>(message.data());
    data_buf.len = static_cast<uint32_t>(message.size());

    azihsm_buffer sig_buf{};
    sig_buf.ptr = const_cast<uint8_t *>(signature.data());
    sig_buf.len = static_cast<uint32_t>(signature.size());

    return azihsm_crypt_verify(&sign_algo, public_key, &data_buf, &sig_buf);
}

azihsm_status unwrap_wrapped_ecc_pair_with_configs(
    azihsm_handle session,
    azihsm_ecc_curve curve,
    const RsaAesWrapConfig &wrap_config,
    const RsaAesWrapConfig &unwrap_config,
    UnwrapPairResult &unwrap_result
)
{
    auto_key rsa_priv_key;
    auto_key rsa_pub_key;
    auto err =
        generate_rsa_unwrapping_keypair(session, rsa_priv_key.get_ptr(), rsa_pub_key.get_ptr());
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    std::vector<uint8_t> wrapped_blob;
    err = make_wrapped_ecc_pkcs8_blob(rsa_pub_key.get(), curve, wrap_config, wrapped_blob);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    azihsm_buffer wrapped_key_buf{};
    wrapped_key_buf.ptr = wrapped_blob.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

    RsaAesUnwrapAlgo unwrap_algo(unwrap_config);

    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;
    priv_props.ecc_curve = curve;
    pub_props.ecc_curve = curve;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    unwrap_result = try_unwrap_pair(
        &unwrap_algo.algo,
        rsa_priv_key.get(),
        &wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list
    );
    return AZIHSM_STATUS_SUCCESS;
}

// Wraps caller-provided plaintext with RSA-AES transport parameters and returns wrapped bytes.
azihsm_status wrap_plaintext_with_rsa_aes(
    azihsm_handle wrapping_pub_key,
    const std::vector<uint8_t> &plaintext,
    const RsaAesWrapConfig &wrap_config,
    std::vector<uint8_t> &wrapped_blob
)
{
    if (plaintext.empty())
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    azihsm_algo_rsa_pkcs_oaep_params oaep_params{};
    oaep_params.hash_algo_id = wrap_config.hash_algo;
    oaep_params.mgf1_hash_algo_id = wrap_config.mgf1_hash_algo;
    oaep_params.label = wrap_config.label;

    azihsm_algo_rsa_aes_wrap_params wrap_params{};
    wrap_params.oaep_params = &oaep_params;
    wrap_params.aes_key_bits = wrap_config.aes_key_bits;

    azihsm_algo wrap_algo{};
    wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
    wrap_algo.params = &wrap_params;
    wrap_algo.len = sizeof(wrap_params);

    azihsm_buffer in_buf{};
    in_buf.ptr = const_cast<uint8_t *>(plaintext.data());
    in_buf.len = static_cast<uint32_t>(plaintext.size());

    azihsm_buffer out_buf{};
    out_buf.ptr = nullptr;
    out_buf.len = 0;

    auto err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &in_buf, &out_buf);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL || out_buf.len == 0)
    {
        wrapped_blob.clear();
        return err;
    }

    wrapped_blob.resize(out_buf.len);
    out_buf.ptr = wrapped_blob.data();

    err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &in_buf, &out_buf);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        wrapped_blob.clear();
        return err;
    }

    wrapped_blob.resize(out_buf.len);
    return AZIHSM_STATUS_SUCCESS;
}

// Builds deterministic plaintext bytes used as wrapped input content in negative unwrap tests.
std::vector<uint8_t> make_deterministic_payload(uint8_t seed, uint8_t step, size_t len)
{
    std::vector<uint8_t> plaintext_bytes;
    plaintext_bytes.reserve(len);

    uint8_t value = seed;
    for (size_t i = 0; i < len; ++i)
    {
        plaintext_bytes.push_back(value);
        value = static_cast<uint8_t>(value + step);
    }

    return plaintext_bytes;
}

// Initializes `ctx` by generating an RSA unwrapping key pair on the given
// session.  The resulting private/public key handles are stored in
// ctx.rsa_priv_key and ctx.rsa_pub_key.  No wrapped blob is produced;
// use create_with_wrapped_blob() when a real ciphertext is needed.
azihsm_status UnwrapPairContext::create(azihsm_handle session, UnwrapPairContext &ctx)
{
    return generate_rsa_unwrapping_keypair(
        session,
        ctx.rsa_priv_key.get_ptr(),
        ctx.rsa_pub_key.get_ptr()
    );
}

// Convenience overload that delegates to the full create_with_wrapped_blob()
// using default wrap configuration (SHA-256, 256-bit AES, no label).
azihsm_status UnwrapPairContext::create_with_wrapped_blob(
    azihsm_handle session,
    azihsm_ecc_curve curve,
    UnwrapPairContext &ctx
)
{
    return create_with_wrapped_blob(session, curve, RsaAesWrapConfig{}, ctx);
}

// Initializes `ctx` with an RSA key pair *and* a wrapped ECC PKCS#8 blob.
// Generates the RSA pair, then wraps a freshly-generated ECC key of the
// requested `curve` using RSA-AES with `wrap_config`.  After success the
// caller can immediately call try_unwrap() or try_unwrap_inputs() on ctx.
azihsm_status UnwrapPairContext::create_with_wrapped_blob(
    azihsm_handle session,
    azihsm_ecc_curve curve,
    const RsaAesWrapConfig &wrap_config,
    UnwrapPairContext &ctx
)
{
    auto err = create(session, ctx);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    err = make_wrapped_ecc_pkcs8_blob(ctx.rsa_pub_key.get(), curve, wrap_config, ctx.wrapped_blob);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    ctx.wrapped_key_buf.ptr = ctx.wrapped_blob.data();
    ctx.wrapped_key_buf.len = static_cast<uint32_t>(ctx.wrapped_blob.size());
    ctx.priv_props.ecc_curve = curve;
    ctx.pub_props.ecc_curve = curve;
    return AZIHSM_STATUS_SUCCESS;
}

// Attempts unwrap using the context's own algo and wrapped buffer.
// Requires a prior create_with_wrapped_blob() call so that
// unwrap_algo and wrapped_key_buf are populated.
UnwrapPairResult UnwrapPairContext::try_unwrap()
{
    return try_unwrap_with_algo(&unwrap_algo.algo);
}

// Attempts unwrap with a caller-supplied algorithm descriptor, keeping
// the context's own RSA key and wrapped buffer.  Useful for testing
// invalid or mutated algorithm structs against a valid key pair.
UnwrapPairResult UnwrapPairContext::try_unwrap_with_algo(azihsm_algo *algo)
{
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();
    return try_unwrap_pair(
        algo,
        rsa_priv_key.get(),
        &wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list
    );
}

// Attempts unwrap with a caller-supplied unwrapping key handle, keeping
// the context's own algorithm and wrapped buffer.  Useful for testing
// wrong key type, stale handle, or cross-session key scenarios.
UnwrapPairResult UnwrapPairContext::try_unwrap_with_key(azihsm_handle key)
{
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();
    return try_unwrap_pair(
        &unwrap_algo.algo,
        key,
        &wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list
    );
}

// Most flexible unwrap helper — caller supplies both the algorithm and
// wrapped-key buffer while the context provides the RSA key and
// property lists.  Other try_unwrap_* variants delegate here.
UnwrapPairResult UnwrapPairContext::try_unwrap_with(azihsm_algo *algo, azihsm_buffer *wrapped_key)
{
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();
    return try_unwrap_pair(algo, rsa_priv_key.get(), wrapped_key, &priv_prop_list, &pub_prop_list);
}

// Shorthand that extracts the algo and wrapped buffer from an
// RsaAesUnwrapPairInputs struct and forwards to try_unwrap_with().
// Ideal for tests that mutate a single field on the inputs struct.
UnwrapPairResult UnwrapPairContext::try_unwrap_inputs(RsaAesUnwrapPairInputs &inputs)
{
    return try_unwrap_with(&inputs.unwrap_algo, &inputs.wrapped_key_buf);
}

// Calls azihsm_key_unwrap_pair directly, giving the caller full control
// over the output-handle pointers (which may be null or aliased).
// Used by tests that validate null/aliased output-handle rejection.
azihsm_status UnwrapPairContext::raw_unwrap(
    RsaAesUnwrapPairInputs &inputs,
    azihsm_handle *priv_out,
    azihsm_handle *pub_out
)
{
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();
    return azihsm_key_unwrap_pair(
        &inputs.unwrap_algo,
        rsa_priv_key.get(),
        &inputs.wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list,
        priv_out,
        pub_out
    );
}

// Exercises unwrap with a fabricated (invalid) key handle and dummy
// inputs — no HSM session required.  Verifies that the API rejects
// bad handle values (zero, non-existent, wrong type) before touching
// any session state.
UnwrapPairResult try_unwrap_with_invalid_handle(azihsm_handle key_handle)
{
    RsaAesUnwrapPairInputs inputs(0xAB);
    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();
    return try_unwrap_pair(
        &inputs.unwrap_algo,
        key_handle,
        &inputs.wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list
    );
}

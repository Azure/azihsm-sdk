#pragma once

#include <azihsm_api.h>
#include <vector>

// Generic RAII wrapper for managing an existing HSM key with automatic cleanup
struct AutoKey
{
    azihsm_handle handle = 0;

    AutoKey() = default;

    // Prevent copying
    AutoKey(const AutoKey &) = delete;
    AutoKey &operator=(const AutoKey &) = delete;

    // Allow moving
    AutoKey(AutoKey &&other) noexcept : handle(other.handle)
    {
        other.handle = 0;
    }

    AutoKey &operator=(AutoKey &&other) noexcept
    {
        if (this != &other)
        {
            if (handle != 0)
            {
                azihsm_key_delete(handle);
            }
            handle = other.handle;
            other.handle = 0;
        }
        return *this;
    }

    ~AutoKey()
    {
        if (handle != 0)
        {
            azihsm_key_delete(handle);
        }
    }

    azihsm_handle get() const
    {
        return handle;
    }
    azihsm_handle *get_ptr()
    {
        return &handle;
    }

    // Allow implicit conversion to azihsm_handle for convenience
    operator azihsm_handle() const
    {
        return handle;
    }

    azihsm_handle release()
    {
        azihsm_handle temp = handle;
        handle = 0;
        return temp;
    }
};

/// Key properties for importing keys
typedef struct _KeyProps
{
    azihsm_key_kind key_kind;
    uint32_t key_size_bits;
    bool session_key = true;
    bool sign = false;
    bool verify = false;
    bool encrypt = false;
    bool decrypt = false;
    bool derive = false;
    bool wrap = false;
    bool unwrap = false;
} KeyProps;

/// Helper function to generate RSA unwrapping key pair for testing
inline azihsm_status generate_rsa_unwrapping_keypair(
    azihsm_handle session,
    azihsm_handle *priv_key_handle,
    azihsm_handle *pub_key_handle
)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    KeyProps props = {
        .key_kind = AZIHSM_KEY_KIND_RSA,
        .key_size_bits = 2048,
        .session_key = false,
        .wrap = true,
        .unwrap = true,
    };

    azihsm_key_class priv_key_class = AZIHSM_KEY_CLASS_PRIVATE;
    azihsm_key_class pub_key_class = AZIHSM_KEY_CLASS_PUBLIC;

    // Private key properties
    std::vector<azihsm_key_prop> priv_props_vec = std::vector<azihsm_key_prop>{
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
          .val = &props.key_size_bits,
          .len = sizeof(props.key_size_bits) },
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &priv_key_class, .len = sizeof(priv_key_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &props.key_kind, .len = sizeof(props.key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_SESSION,
          .val = &props.session_key,
          .len = sizeof(props.session_key) },
        { .id = AZIHSM_KEY_PROP_ID_UNWRAP, .val = &props.unwrap, .len = sizeof(props.unwrap) }
    };

    azihsm_key_prop_list priv_prop_list{ .props = priv_props_vec.data(),
                                         .count = static_cast<uint32_t>(priv_props_vec.size()) };

    // Public key properties
    std::vector<azihsm_key_prop> pub_props_vec = std::vector<azihsm_key_prop>{
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
          .val = &props.key_size_bits,
          .len = sizeof(props.key_size_bits) },
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &pub_key_class, .len = sizeof(pub_key_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &props.key_kind, .len = sizeof(props.key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_SESSION,
          .val = &props.session_key,
          .len = sizeof(props.session_key) },
        { .id = AZIHSM_KEY_PROP_ID_WRAP, .val = &props.wrap, .len = sizeof(props.wrap) }
    };

    azihsm_key_prop_list pub_prop_list{ .props = pub_props_vec.data(),
                                        .count = static_cast<uint32_t>(pub_props_vec.size()) };

    return azihsm_key_gen_pair(
        session,
        &keygen_algo,
        &priv_prop_list,
        &pub_prop_list,
        priv_key_handle,
        pub_key_handle
    );
}

/// Helper function to import a key pair (RSA or ECC) using RSA-AES key wrapping
inline azihsm_status import_keypair(
    azihsm_handle wrapping_pub_key,
    azihsm_handle wrapping_priv_key,
    const std::vector<uint8_t> &key_der,
    KeyProps props,
    azihsm_handle *imported_priv_key,
    azihsm_handle *imported_pub_key
)
{
    // Step 1: Setup RSA-AES wrapping algorithm
    azihsm_algo_rsa_pkcs_oaep_params oaep_params = {};
    oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
    oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
    oaep_params.label = nullptr;

    azihsm_algo_rsa_aes_wrap_params wrap_params = {};
    wrap_params.oaep_params = &oaep_params;
    wrap_params.aes_key_bits = 256; // AES-256

    azihsm_algo wrap_algo = {};
    wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
    wrap_algo.params = &wrap_params;
    wrap_algo.len = sizeof(wrap_params);

    // Step 2: Wrap the DER-encoded key
    azihsm_buffer input_key = {};
    input_key.ptr = const_cast<uint8_t *>(key_der.data());
    input_key.len = static_cast<uint32_t>(key_der.size());

    std::vector<uint8_t> wrapped_key_data(4096);
    azihsm_buffer wrapped_key_buf = {};
    wrapped_key_buf.ptr = wrapped_key_data.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_key_data.size());

    auto wrap_err =
        azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &input_key, &wrapped_key_buf);
    if (wrap_err != AZIHSM_STATUS_SUCCESS)
    {
        return wrap_err;
    }

    // Step 3: Setup unwrap algorithm
    azihsm_algo_rsa_aes_key_wrap_params unwrap_params = {};
    unwrap_params.oaep_params = &oaep_params;

    azihsm_algo unwrap_algo = {};
    unwrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP;
    unwrap_algo.params = &unwrap_params;
    unwrap_algo.len = sizeof(unwrap_params);

    // Step 4: Setup key properties based on key kind
    azihsm_key_class priv_key_class = AZIHSM_KEY_CLASS_PRIVATE;
    azihsm_key_class pub_key_class = AZIHSM_KEY_CLASS_PUBLIC;

    std::vector<azihsm_key_prop> priv_props_vec;
    std::vector<azihsm_key_prop> pub_props_vec;

    if (props.key_kind == AZIHSM_KEY_KIND_RSA)
    {
        // RSA private key properties (decrypt and sign capabilities)
        priv_props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
              .val = &props.key_size_bits,
              .len = sizeof(props.key_size_bits) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS,
              .val = &priv_key_class,
              .len = sizeof(priv_key_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND,
              .val = &props.key_kind,
              .len = sizeof(props.key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION,
              .val = &props.session_key,
              .len = sizeof(props.session_key) },
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT,
              .val = &props.decrypt,
              .len = sizeof(props.decrypt) },
            { .id = AZIHSM_KEY_PROP_ID_SIGN, .val = &props.sign, .len = sizeof(props.sign) }
        };

        // RSA public key properties (encrypt and verify capabilities)
        pub_props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
              .val = &props.key_size_bits,
              .len = sizeof(props.key_size_bits) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &pub_key_class, .len = sizeof(pub_key_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND,
              .val = &props.key_kind,
              .len = sizeof(props.key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION,
              .val = &props.session_key,
              .len = sizeof(props.session_key) },
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT,
              .val = &props.encrypt,
              .len = sizeof(props.encrypt) },
            { .id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &props.verify, .len = sizeof(props.verify) }
        };
    }
    else if (props.key_kind == AZIHSM_KEY_KIND_ECC)
    {
        // Determine ECC curve from key size
        azihsm_ecc_curve curve;
        switch (props.key_size_bits)
        {
        case 256:
            curve = AZIHSM_ECC_CURVE_P256;
            break;
        case 384:
            curve = AZIHSM_ECC_CURVE_P384;
            break;
        case 521:
            curve = AZIHSM_ECC_CURVE_P521;
            break;
        default:
            return AZIHSM_STATUS_INVALID_ARGUMENT;
        }

        // ECC private key properties (sign capability)
        priv_props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS,
              .val = &priv_key_class,
              .len = sizeof(priv_key_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND,
              .val = &props.key_kind,
              .len = sizeof(props.key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION,
              .val = &props.session_key,
              .len = sizeof(props.session_key) },
            { .id = AZIHSM_KEY_PROP_ID_SIGN, .val = &props.sign, .len = sizeof(props.sign) }
        };

        // ECC public key properties (verify capability)
        pub_props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &pub_key_class, .len = sizeof(pub_key_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND,
              .val = &props.key_kind,
              .len = sizeof(props.key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION,
              .val = &props.session_key,
              .len = sizeof(props.session_key) },
            { .id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &props.verify, .len = sizeof(props.verify) }
        };
    }
    else
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    azihsm_key_prop_list priv_key_props = { .props = priv_props_vec.data(),
                                            .count = static_cast<uint32_t>(priv_props_vec.size()) };

    azihsm_key_prop_list pub_key_props = { .props = pub_props_vec.data(),
                                           .count = static_cast<uint32_t>(pub_props_vec.size()) };

    // Step 5: Unwrap the key pair
    return azihsm_key_unwrap_pair(
        &unwrap_algo,
        wrapping_priv_key,
        &wrapped_key_buf,
        &priv_key_props,
        &pub_key_props,
        imported_priv_key,
        imported_pub_key
    );
}
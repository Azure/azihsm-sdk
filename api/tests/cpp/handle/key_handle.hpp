// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef KEY_HANDLE_HPP
#define KEY_HANDLE_HPP

#include <azihsm_api.h>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

/// Key properties for key generation.
/// Mirrors the Rust HsmKeyProps structure.
struct KeyProps
{
    uint32_t key_class;
    uint32_t key_kind;
    uint32_t bits;
    bool is_session;
    bool can_encrypt;
    bool can_decrypt;
    bool can_sign;
    bool can_verify;
    bool can_wrap;
    bool can_unwrap;
    bool can_derive;

    KeyProps()
        : key_class(0), key_kind(0), bits(0), is_session(true), can_encrypt(false),
          can_decrypt(false), can_sign(false), can_verify(false), can_wrap(false),
          can_unwrap(false), can_derive(false)
    {
    }
};

class KeyHandle
{
  public:
    KeyHandle(azihsm_handle sess_handle, const azihsm_algo *algo, const KeyProps &props)
        : handle_(0), key_class_(props.key_class), key_kind_(props.key_kind), bits_(props.bits),
          session_(props.is_session ? 1 : 0), encrypt_(props.can_encrypt ? 1 : 0),
          decrypt_(props.can_decrypt ? 1 : 0), sign_(props.can_sign ? 1 : 0),
          verify_(props.can_verify ? 1 : 0), wrap_(props.can_wrap ? 1 : 0),
          unwrap_(props.can_unwrap ? 1 : 0), derive_(props.can_derive ? 1 : 0)
    {
        // Build property list
        std::vector<azihsm_key_prop> prop_list;

        prop_list.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class_, sizeof(key_class_) });
        prop_list.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind_, sizeof(key_kind_) });
        prop_list.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &session_, sizeof(session_) });
        prop_list.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits_, sizeof(bits_) });
        prop_list.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &encrypt_, sizeof(encrypt_) });
        prop_list.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &decrypt_, sizeof(decrypt_) });
        prop_list.push_back({ AZIHSM_KEY_PROP_ID_SIGN, &sign_, sizeof(sign_) });
        prop_list.push_back({ AZIHSM_KEY_PROP_ID_VERIFY, &verify_, sizeof(verify_) });
        prop_list.push_back({ AZIHSM_KEY_PROP_ID_WRAP, &wrap_, sizeof(wrap_) });
        prop_list.push_back({ AZIHSM_KEY_PROP_ID_UNWRAP, &unwrap_, sizeof(unwrap_) });
        prop_list.push_back({ AZIHSM_KEY_PROP_ID_DERIVE, &derive_, sizeof(derive_) });

        azihsm_key_prop_list list{ prop_list.data(), static_cast<uint32_t>(prop_list.size()) };

        auto err = azihsm_key_gen(sess_handle, algo, &list, &handle_);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error("Failed to generate key. Error: " + std::to_string(err));
        }
    }

    ~KeyHandle() noexcept
    {
        if (handle_ != 0)
        {
            azihsm_key_delete(handle_);
        }
    }

    KeyHandle(const KeyHandle &) = delete;
    KeyHandle &operator=(const KeyHandle &) = delete;

    KeyHandle(KeyHandle &&other) noexcept
        : handle_(other.handle_), key_class_(other.key_class_), key_kind_(other.key_kind_),
          bits_(other.bits_), session_(other.session_), encrypt_(other.encrypt_),
          decrypt_(other.decrypt_), sign_(other.sign_), verify_(other.verify_), wrap_(other.wrap_),
          unwrap_(other.unwrap_), derive_(other.derive_)
    {
        other.handle_ = 0;
    }

    KeyHandle &operator=(KeyHandle &&other) noexcept
    {
        if (this != &other)
        {
            if (handle_ != 0)
            {
                azihsm_key_delete(handle_);
            }
            handle_ = other.handle_;
            key_class_ = other.key_class_;
            key_kind_ = other.key_kind_;
            bits_ = other.bits_;
            session_ = other.session_;
            encrypt_ = other.encrypt_;
            decrypt_ = other.decrypt_;
            sign_ = other.sign_;
            verify_ = other.verify_;
            wrap_ = other.wrap_;
            unwrap_ = other.unwrap_;
            derive_ = other.derive_;
            other.handle_ = 0;
        }
        return *this;
    }

    azihsm_handle get() const noexcept
    {
        return handle_;
    }

    explicit operator bool() const noexcept
    {
        return handle_ != 0;
    }

  private:
    azihsm_handle handle_;

    // Store property values as members to ensure they outlive the azihsm_key_gen call
    uint32_t key_class_;
    uint32_t key_kind_;
    uint32_t bits_;
    uint8_t session_;
    uint8_t encrypt_;
    uint8_t decrypt_;
    uint8_t sign_;
    uint8_t verify_;
    uint8_t wrap_;
    uint8_t unwrap_;
    uint8_t derive_;
};

#endif // KEY_HANDLE_HPP
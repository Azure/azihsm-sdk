// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "kat.hpp"
#include "utils/rsa_keygen.hpp"
#include <vector>

auto_key import_local_aes_key_for_kat(
	azihsm_handle session,
	const uint8_t *local_key_data,
	size_t local_key_len,
	uint32_t aes_key_bits
)
{
	auto_key wrapping_priv_key;
	auto_key wrapping_pub_key;
	auto err = generate_rsa_unwrapping_keypair(
		session,
		wrapping_priv_key.get_ptr(),
		wrapping_pub_key.get_ptr()
	);
	if (err != AZIHSM_STATUS_SUCCESS)
	{
		return {};
	}

	azihsm_algo_rsa_pkcs_oaep_params oaep_params{};
	oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
	oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
	oaep_params.label = nullptr;

	azihsm_algo_rsa_aes_wrap_params wrap_params{};
	wrap_params.oaep_params = &oaep_params;
	wrap_params.aes_key_bits = aes_key_bits;

	azihsm_algo wrap_algo{};
	wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
	wrap_algo.params = &wrap_params;
	wrap_algo.len = sizeof(wrap_params);

	azihsm_buffer local_key_buf{};
	local_key_buf.ptr = const_cast<uint8_t *>(local_key_data);
	local_key_buf.len = static_cast<uint32_t>(local_key_len);

	azihsm_buffer wrapped_buf{};
	wrapped_buf.ptr = nullptr;
	wrapped_buf.len = 0;

	err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key.get(), &local_key_buf, &wrapped_buf);
	if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
	{
		return {};
	}

	std::vector<uint8_t> wrapped_data(wrapped_buf.len);
	wrapped_buf.ptr = wrapped_data.data();

	err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key.get(), &local_key_buf, &wrapped_buf);
	if (err != AZIHSM_STATUS_SUCCESS)
	{
		return {};
	}

	azihsm_algo_rsa_aes_key_wrap_params unwrap_params{};
	unwrap_params.oaep_params = &oaep_params;

	azihsm_algo unwrap_algo{};
	unwrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP;
	unwrap_algo.params = &unwrap_params;
	unwrap_algo.len = sizeof(unwrap_params);

	azihsm_key_kind aes_kind = AZIHSM_KEY_KIND_AES;
	azihsm_key_class aes_class = AZIHSM_KEY_CLASS_SECRET;
	bool aes_is_session = true;
	bool can_encrypt = true;
	bool can_decrypt = true;

	std::vector<azihsm_key_prop> unwrap_props_vec;
	unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &aes_kind, sizeof(aes_kind) });
	unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &aes_class, sizeof(aes_class) });
	unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &aes_key_bits, sizeof(aes_key_bits) });
	unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &aes_is_session, sizeof(aes_is_session) });
	unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
	unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

	azihsm_key_prop_list unwrap_prop_list{
		unwrap_props_vec.data(),
		static_cast<uint32_t>(unwrap_props_vec.size())
	};

	azihsm_buffer wrapped_key_buf{};
	wrapped_key_buf.ptr = wrapped_data.data();
	wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

	auto_key unwrapped_key;
	err = azihsm_key_unwrap(
		&unwrap_algo,
		wrapping_priv_key.get(),
		&wrapped_key_buf,
		&unwrap_prop_list,
		unwrapped_key.get_ptr()
	);
	if (err != AZIHSM_STATUS_SUCCESS)
	{
		return {};
	}

	return unwrapped_key;
}

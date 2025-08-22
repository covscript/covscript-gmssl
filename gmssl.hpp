#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/hex_lower.hpp>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <random>

namespace gmssl {
	using uint8_array_t = std::vector<uint8_t>;
	std::string rand_bytes(size_t count, std::mt19937::result_type seed = std::mt19937::default_seed)
	{
		constexpr char raw_bytes[] = "1234567890!@#$%^&*?/-=_+abcdefghijklmnopqrstuvwxyz";
		if (seed == std::mt19937::default_seed) {
			std::random_device rd;
			seed = rd();
		}
		std::mt19937 generator(seed);
		std::string result;
		result.reserve(count);
		for (size_t i = 0; i < count; ++i)
			result += raw_bytes[std::uniform_int_distribution<size_t>(0, sizeof(raw_bytes))(generator)];
		return result;
	}
	uint8_array_t bytes_encode(const std::string &str)
	{
		return uint8_array_t(str.begin(), str.end());
	}
	std::string bytes_decode(const uint8_array_t &arr)
	{
		return std::string(arr.begin(), arr.end());
	}
	uint8_array_t hex_encode(const uint8_array_t &arr)
	{
		return cppcodec::hex_lower::encode<uint8_array_t>(arr);
	}
	uint8_array_t hex_decode(const uint8_array_t &arr)
	{
		return cppcodec::hex_lower::decode<uint8_array_t>(arr);
	}
	uint8_array_t base64_encode(const uint8_array_t &arr)
	{
		return cppcodec::base64_rfc4648::encode<uint8_array_t>(arr);
	}
	uint8_array_t base64_decode(const uint8_array_t &arr)
	{
		return cppcodec::base64_rfc4648::decode<uint8_array_t>(arr);
	}
	uint8_array_t sm3_digest(const uint8_array_t &input_data)
	{
		SM3_DIGEST_CTX ctx;

		if (sm3_digest_init(&ctx, nullptr, 0) != 1)
			throw std::runtime_error("GmSSL SM3 context init failed.");

		if (sm3_digest_update(&ctx, input_data.data(), input_data.size()) != 1)
			throw std::runtime_error("GmSSL SM3 update error.");

		uint8_array_t raw_hash(SM3_DIGEST_SIZE);
		if (sm3_digest_finish(&ctx, raw_hash.data()) != 1)
			throw std::runtime_error("GmSSL SM3 finish failed.");

		return raw_hash;
	}
	enum class sm4_mode : uint8_t {
		cbc_encrypt = 0b00,
		cbc_decrypt = 0b01,
		ctr_encrypt = 0b10,
		ctr_decrypt = 0b11,
	};
	constexpr size_t sm4_key_size = SM4_KEY_SIZE;
	uint8_array_t sm4(sm4_mode action, const std::string &key, const std::string &init_vec, const uint8_array_t &input_bytes, size_t buff_size = 4096)
	{
		if (key.size() != sm4_key_size || init_vec.size() != sm4_key_size)
			throw std::runtime_error("GmSSL SM4 key or iv size error.");

		union {
			SM4_CBC_CTX cbc;
			SM4_CTR_CTX ctr;
		} ctx;

		if (((uint8_t)action & 0b10 ? sm4_ctr_encrypt_init(&ctx.ctr, (const uint8_t *)key.c_str(), (const uint8_t *)init_vec.c_str()) : ((uint8_t)action & 0b01 ? sm4_cbc_decrypt_init(&ctx.cbc, (const uint8_t *)key.c_str(), (const uint8_t *)init_vec.c_str()) : sm4_cbc_encrypt_init(&ctx.cbc, (const uint8_t *)key.c_str(), (const uint8_t *)init_vec.c_str()))) != 1)
			throw std::runtime_error("GmSSL SM4 context init failed.");

		std::vector<uint8_t> output_bytes;
		uint8_t buff[buff_size];
		size_t outlen = 0;
		size_t offset = 0;

		while (offset < input_bytes.size()) {
			size_t inlen = offset + buff_size >= input_bytes.size() ? input_bytes.size() - offset : buff_size;
			if (((uint8_t)action & 0b10 ? sm4_ctr_encrypt_update(&ctx.ctr, input_bytes.data() + offset, inlen, buff, &outlen) : ((uint8_t)action & 0b01 ? sm4_cbc_decrypt_update(&ctx.cbc, input_bytes.data() + offset, inlen, buff, &outlen) : sm4_cbc_encrypt_update(&ctx.cbc, input_bytes.data() + offset, inlen, buff, &outlen))) != 1)
				throw std::runtime_error((uint8_t)action & 0b01 ? "GmSSL SM4 decrypt error." : "GmSSL SM4 encrypt error.");

			if (outlen > 0)
				output_bytes.insert(output_bytes.end(), buff, buff + outlen);

			offset += inlen;
		}

		if (((uint8_t)action & 0b10 ? sm4_ctr_encrypt_finish(&ctx.ctr, buff, &outlen) : ((uint8_t)action & 0b01 ? sm4_cbc_decrypt_finish(&ctx.cbc, buff, &outlen) : sm4_cbc_encrypt_finish(&ctx.cbc, buff, &outlen))) != 1)
			throw std::runtime_error((uint8_t)action & 0b01 ? "GmSSL SM4 decrypt finish failed." : "GmSSL SM4 encrypt finish failed.");

		if (outlen > 0)
			output_bytes.insert(output_bytes.end(), buff, buff + outlen);

		return output_bytes;
	}
}
#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/hex_lower.hpp>
#include <gmssl/rand.h>
#include <gmssl/asn1.h>
#include <gmssl/pem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <stdexcept>
#include <cstring>
#include <string>
#include <vector>
#include <random>
#include <cstdio>

/*
 * Pointer to memset is volatile so that compiler must de-reference
 * the pointer and can't assume that it points to any function in
 * particular (such as memset, which it then might further "optimize")
 */
typedef void *(*memset_t)(void *, int, size_t);

static volatile memset_t memset_func = memset;

void gmssl_secure_clear(void *ptr, size_t len)
{
	memset_func(ptr, 0, len);
}

namespace gmssl {
	using uint8_array_t = std::vector<uint8_t>;
	inline void secure_clear(uint8_array_t &arr)
	{
		gmssl_secure_clear(arr.data(), arr.size());
	}
	constexpr size_t buff_size = 2048;
	std::string rand_bytes(size_t count, std::mt19937::result_type seed = 0)
	{
		constexpr char charset[] =
		    "0123456789"
		    "abcdefghijklmnopqrstuvwxyz"
		    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		    "!@#$%^&*()-_=+[]{};:',.<>/?";
		// Skip final '\0'
		constexpr size_t charset_size = sizeof(charset) / sizeof(charset[0]) - 1;

		if (count == 0)
			throw std::runtime_error("Count == 0");

		if (seed == 0) {
			std::random_device rd;
			seed = rd();
		}

		std::mt19937 generator(seed);
		std::string result(count, '\0');
		std::uniform_int_distribution<int> dist(0, charset_size - 1);
		for (size_t i = 0; i < count; ++i)
			result[i] = charset[dist(generator)];

		return result;
	}
	inline uint8_array_t bytes_encode(const std::string &str)
	{
		return uint8_array_t(str.begin(), str.end());
	}
	inline std::string bytes_decode(const uint8_array_t &arr)
	{
		return std::string(arr.begin(), arr.end());
	}
	inline uint8_array_t hex_encode(const uint8_array_t &arr)
	{
		return cppcodec::hex_lower::encode<uint8_array_t>(arr);
	}
	inline uint8_array_t hex_decode(const uint8_array_t &arr)
	{
		return cppcodec::hex_lower::decode<uint8_array_t>(arr);
	}
	inline uint8_array_t base64_encode(const uint8_array_t &arr)
	{
		return cppcodec::base64_rfc4648::encode<uint8_array_t>(arr);
	}
	inline uint8_array_t base64_decode(const uint8_array_t &arr)
	{
		return cppcodec::base64_rfc4648::decode<uint8_array_t>(arr);
	}
	uint8_array_t sm2_pem_read(const std::string &path)
	{
		FILE *fp = fopen(path.c_str(), "rb");
		if (!fp)
			throw std::runtime_error("GmSSL SM2 PEM file can not open.");

		uint8_array_t buf(buff_size);
		size_t len = 0;
		int rc = pem_read(fp, "EC PRIVATE KEY", buf.data(), &len, buf.size());
		fclose(fp);
		if (rc != 1) {
			gmssl_secure_clear(buf.data(), buf.size());
			throw std::runtime_error("GmSSL SM2 read PEM file failed.");
		}

		uint8_array_t ret(buf.begin(), buf.begin() + len);

		gmssl_secure_clear(buf.data(), buf.size());

		return std::move(ret);
	}
	void sm2_pem_write(const std::string &path, const uint8_array_t &data)
	{
		FILE *fp = fopen(path.c_str(), "wb");
		if (!fp)
			throw std::runtime_error("GmSSL SM2 PEM file can not open.");

		int rc = pem_write(fp, "EC PRIVATE KEY", data.data(), data.size());
		fclose(fp);
		if (rc != 1)
			throw std::runtime_error("GmSSL SM2 write PEM file failed.");
	}
	void sm2_key_generate(uint8_array_t &pubkey, uint8_array_t &privkey, const std::string &passwd)
	{
		SM2_KEY key;
		if (::sm2_key_generate(&key) != 1)
			throw std::runtime_error("GmSSL SM2 key generate failed.");

		uint8_array_t buf(buff_size);
		uint8_t *p = buf.data();
		size_t len = 0;
		if (sm2_public_key_info_to_der(&key, &p, &len) != 1 || len == 0) {
			gmssl_secure_clear(buf.data(), buf.size());
			throw std::runtime_error("GmSSL SM2 public key encode failed.");
		}

		pubkey.assign(buf.data(), buf.data() + len);
		gmssl_secure_clear(buf.data(), buf.size());
		p = buf.data();
		len = 0;
		if (sm2_private_key_info_encrypt_to_der(&key, passwd.c_str(), &p, &len) != 1 || len == 0) {
			gmssl_secure_clear(buf.data(), buf.size());
			throw std::runtime_error("GmSSL SM2 private key encode failed.");
		}

		privkey.assign(buf.data(), buf.data() + len);
		gmssl_secure_clear(buf.data(), buf.size());
	}
	uint8_array_t sm2_sign(const uint8_array_t &privkey, const std::string &passwd, const std::string &id, const uint8_array_t &input_bytes)
	{
		if (privkey.size() == 0)
			throw std::runtime_error("GmSSL SM2 private key is empty.");

		if (input_bytes.size() == 0)
			throw std::runtime_error("GmSSL SM2 data size invalid.");

		SM2_KEY key;
		uint8_array_t keybuf(buff_size);
		if (privkey.size() > keybuf.size())
			throw std::runtime_error("GmSSL SM2 private key too large.");

		std::memcpy(keybuf.data(), privkey.data(), privkey.size());
		const uint8_t *keyp = keybuf.data();
		size_t keylen = privkey.size();
		const uint8_t *attrs = nullptr;
		size_t attrs_len = 0;

		if (sm2_private_key_info_decrypt_from_der(&key, &attrs, &attrs_len, passwd.c_str(), &keyp, &keylen) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 private key decode failed.");
		}

		if (!asn1_length_is_zero(keylen)) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 extra bytes after private key decode.");
		}

		SM2_SIGN_CTX ctx;
		if (sm2_sign_init(&ctx, &key, id.c_str(), id.size()) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 sign init failed.");
		}

		uint8_array_t sig(SM2_MAX_SIGNATURE_SIZE);
		size_t outlen = 0;
		size_t offset = 0;

		while (offset < input_bytes.size()) {
			size_t inlen = offset + buff_size >= input_bytes.size() ? input_bytes.size() - offset : buff_size;
			if (sm2_sign_update(&ctx, input_bytes.data() + offset, inlen) != 1) {
				gmssl_secure_clear(&key, sizeof(key));
				gmssl_secure_clear(&ctx, sizeof(ctx));
				gmssl_secure_clear(keybuf.data(), keybuf.size());
				gmssl_secure_clear(sig.data(), sig.size());
				throw std::runtime_error("GmSSL SM2 sign update failed.");
			}
			offset += inlen;
		}

		if (sm2_sign_finish(&ctx, sig.data(), &outlen) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			gmssl_secure_clear(sig.data(), sig.size());
			throw std::runtime_error("GmSSL SM2 sign finish failed.");
		}

		uint8_array_t ret(sig.data(), sig.data() + outlen);

		gmssl_secure_clear(&key, sizeof(key));
		gmssl_secure_clear(&ctx, sizeof(ctx));
		gmssl_secure_clear(keybuf.data(), keybuf.size());
		gmssl_secure_clear(sig.data(), sig.size());

		return std::move(ret);
	}
	uint8_array_t sm2_sign_stream(const uint8_array_t &privkey, const std::string &passwd, const std::string &id, std::istream &is)
	{
		if (privkey.size() == 0)
			throw std::runtime_error("GmSSL SM2 private key is empty.");

		if (!is)
			throw std::runtime_error("GmSSL SM2 input stream not available.");

		SM2_KEY key;
		uint8_array_t keybuf(buff_size);
		if (privkey.size() > keybuf.size())
			throw std::runtime_error("GmSSL SM2 private key too large.");

		std::memcpy(keybuf.data(), privkey.data(), privkey.size());
		const uint8_t *keyp = keybuf.data();
		size_t keylen = privkey.size();
		const uint8_t *attrs = nullptr;
		size_t attrs_len = 0;

		if (sm2_private_key_info_decrypt_from_der(&key, &attrs, &attrs_len, passwd.c_str(), &keyp, &keylen) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 private key decode failed.");
		}

		if (!asn1_length_is_zero(keylen)) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 extra bytes after private key decode.");
		}

		SM2_SIGN_CTX ctx;
		if (sm2_sign_init(&ctx, &key, id.c_str(), id.size()) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 sign init failed.");
		}

		uint8_array_t sig(SM2_MAX_SIGNATURE_SIZE);
		uint8_array_t inbuf(buff_size);
		size_t outlen = 0;

		while (is) {
			size_t inlen = is.readsome(reinterpret_cast<char *>(inbuf.data()), buff_size);
			if (sm2_sign_update(&ctx, inbuf.data(), inlen) != 1) {
				gmssl_secure_clear(&key, sizeof(key));
				gmssl_secure_clear(&ctx, sizeof(ctx));
				gmssl_secure_clear(keybuf.data(), keybuf.size());
				gmssl_secure_clear(sig.data(), sig.size());
				gmssl_secure_clear(inbuf.data(), buff_size);
				throw std::runtime_error("GmSSL SM2 sign update failed.");
			}
		}

		if (sm2_sign_finish(&ctx, sig.data(), &outlen) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			gmssl_secure_clear(sig.data(), sig.size());
			gmssl_secure_clear(inbuf.data(), buff_size);
			throw std::runtime_error("GmSSL SM2 sign finish failed.");
		}

		uint8_array_t ret(sig.data(), sig.data() + outlen);

		gmssl_secure_clear(&key, sizeof(key));
		gmssl_secure_clear(&ctx, sizeof(ctx));
		gmssl_secure_clear(keybuf.data(), keybuf.size());
		gmssl_secure_clear(sig.data(), sig.size());
		gmssl_secure_clear(inbuf.data(), buff_size);

		return std::move(ret);
	}
	bool sm2_verify(const uint8_array_t &pubkey, const uint8_array_t &sig, const std::string &id, const uint8_array_t &input_bytes)
	{
		if (pubkey.size() == 0)
			throw std::runtime_error("GmSSL SM2 public key is empty.");

		if (sig.size() == 0 || sig.size() > SM2_MAX_SIGNATURE_SIZE)
			throw std::runtime_error("GmSSL SM2 signature size invalid.");

		if (input_bytes.size() == 0)
			throw std::runtime_error("GmSSL SM2 data size invalid.");

		SM2_KEY key;
		uint8_array_t keybuf(buff_size);
		if (pubkey.size() > keybuf.size())
			throw std::runtime_error("GmSSL SM2 public key too large.");

		std::memcpy(keybuf.data(), pubkey.data(), pubkey.size());
		const uint8_t *keyp = keybuf.data();
		size_t keylen = pubkey.size();
		if (sm2_public_key_info_from_der(&key, &keyp, &keylen) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 public key decode failed.");
		}

		if (!asn1_length_is_zero(keylen)) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 extra bytes after public key decode.");
		}

		SM2_VERIFY_CTX ctx;
		if (sm2_verify_init(&ctx, &key, id.c_str(), id.size()) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 verify init failed.");
		}

		size_t offset = 0;

		while (offset < input_bytes.size()) {
			size_t inlen = offset + buff_size >= input_bytes.size() ? input_bytes.size() - offset : buff_size;
			if (sm2_verify_update(&ctx, input_bytes.data() + offset, inlen) != 1) {
				gmssl_secure_clear(&key, sizeof(key));
				gmssl_secure_clear(&ctx, sizeof(ctx));
				gmssl_secure_clear(keybuf.data(), keybuf.size());
				throw std::runtime_error("GmSSL SM2 verify update failed.");
			}
			offset += inlen;
		}

		int vr = sm2_verify_finish(&ctx, sig.data(), sig.size());

		if (vr < 0)
			throw std::runtime_error("GmSSL SM2 verify finish failed.");

		gmssl_secure_clear(&key, sizeof(key));
		gmssl_secure_clear(&ctx, sizeof(ctx));
		gmssl_secure_clear(keybuf.data(), keybuf.size());

		return vr == 1;
	}
	bool sm2_verify_stream(const uint8_array_t &pubkey, const uint8_array_t &sig, const std::string &id, std::istream &is)
	{
		if (pubkey.size() == 0)
			throw std::runtime_error("GmSSL SM2 public key is empty.");

		if (sig.size() == 0 || sig.size() > SM2_MAX_SIGNATURE_SIZE)
			throw std::runtime_error("GmSSL SM2 signature size invalid.");

		if (!is)
			throw std::runtime_error("GmSSL SM2 input stream not available.");

		SM2_KEY key;
		uint8_array_t keybuf(buff_size);
		if (pubkey.size() > keybuf.size())
			throw std::runtime_error("GmSSL SM2 public key too large.");

		std::memcpy(keybuf.data(), pubkey.data(), pubkey.size());
		const uint8_t *keyp = keybuf.data();
		size_t keylen = pubkey.size();
		if (sm2_public_key_info_from_der(&key, &keyp, &keylen) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 public key decode failed.");
		}

		if (!asn1_length_is_zero(keylen)) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 extra bytes after public key decode.");
		}

		SM2_VERIFY_CTX ctx;
		if (sm2_verify_init(&ctx, &key, id.c_str(), id.size()) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 verify init failed.");
		}

		uint8_array_t inbuf(buff_size);

		while (is) {
			size_t inlen = is.readsome(reinterpret_cast<char *>(inbuf.data()), buff_size);
			if (sm2_verify_update(&ctx, inbuf.data(), inlen) != 1) {
				gmssl_secure_clear(&key, sizeof(key));
				gmssl_secure_clear(&ctx, sizeof(ctx));
				gmssl_secure_clear(keybuf.data(), keybuf.size());
				gmssl_secure_clear(inbuf.data(), buff_size);
				throw std::runtime_error("GmSSL SM2 verify update failed.");
			}
		}

		int vr = sm2_verify_finish(&ctx, sig.data(), sig.size());

		if (vr < 0)
			throw std::runtime_error("GmSSL SM2 verify finish failed.");

		gmssl_secure_clear(&key, sizeof(key));
		gmssl_secure_clear(&ctx, sizeof(ctx));
		gmssl_secure_clear(keybuf.data(), keybuf.size());
		gmssl_secure_clear(inbuf.data(), buff_size);

		return vr == 1;
	}
	uint8_array_t sm2_encrypt(const uint8_array_t &pubkey, const uint8_array_t &input_data)
	{
		if (pubkey.size() == 0)
			throw std::runtime_error("GmSSL SM2 public key is empty.");

		if (input_data.size() == 0 || input_data.size() > SM2_MAX_PLAINTEXT_SIZE)
			throw std::runtime_error("GmSSL SM2 plaintext size invalid.");

		SM2_KEY key;
		uint8_array_t keybuf(buff_size);
		if (pubkey.size() > keybuf.size())
			throw std::runtime_error("GmSSL SM2 public key too large.");

		std::memcpy(keybuf.data(), pubkey.data(), pubkey.size());
		const uint8_t *keyp = keybuf.data();
		size_t keylen = pubkey.size();
		if (sm2_public_key_info_from_der(&key, &keyp, &keylen) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 public key decode failed.");
		}

		if (!asn1_length_is_zero(keylen)) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 extra bytes after public key decode.");
		}

		SM2_ENC_CTX ctx;
		if (sm2_encrypt_init(&ctx) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 encrypt init failed.");
		}

		uint8_array_t outbuf(SM2_MAX_CIPHERTEXT_SIZE);
		size_t outlen = outbuf.size();

		if (sm2_encrypt_update(&ctx, input_data.data(), input_data.size()) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			gmssl_secure_clear(outbuf.data(), outbuf.size());
			throw std::runtime_error("GmSSL SM2 encrypt update failed.");
		}

		if (sm2_encrypt_finish(&ctx, &key, outbuf.data(), &outlen) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			gmssl_secure_clear(outbuf.data(), outbuf.size());
			throw std::runtime_error("GmSSL SM2 encrypt finish failed.");
		}

		uint8_array_t ret(outbuf.begin(), outbuf.begin() + outlen);

		gmssl_secure_clear(&key, sizeof(key));
		gmssl_secure_clear(&ctx, sizeof(ctx));
		gmssl_secure_clear(keybuf.data(), keybuf.size());
		gmssl_secure_clear(outbuf.data(), outbuf.size());

		return std::move(ret);
	}
	uint8_array_t sm2_decrypt(const uint8_array_t &privkey, const std::string &passwd, const uint8_array_t &input_data)
	{
		if (privkey.size() == 0)
			throw std::runtime_error("GmSSL SM2 private key is empty.");

		if (input_data.size() == 0 || input_data.size() > SM2_MAX_CIPHERTEXT_SIZE)
			throw std::runtime_error("GmSSL SM2 ciphertext size invalid.");

		SM2_KEY key;
		uint8_array_t keybuf(buff_size);
		if (privkey.size() > keybuf.size())
			throw std::runtime_error("GmSSL SM2 private key too large.");

		std::memcpy(keybuf.data(), privkey.data(), privkey.size());
		const uint8_t *keyp = keybuf.data();
		size_t keylen = privkey.size();
		const uint8_t *attrs = nullptr;
		size_t attrs_len = 0;

		if (sm2_private_key_info_decrypt_from_der(&key, &attrs, &attrs_len, passwd.c_str(), &keyp, &keylen) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 private key decode failed.");
		}

		if (!asn1_length_is_zero(keylen)) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 extra bytes after private key decode.");
		}

		SM2_DEC_CTX ctx;
		if (sm2_decrypt_init(&ctx) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			throw std::runtime_error("GmSSL SM2 decrypt init failed.");
		}

		uint8_array_t outbuf(SM2_MAX_CIPHERTEXT_SIZE);
		size_t outlen = outbuf.size();

		if (sm2_decrypt_update(&ctx, input_data.data(), input_data.size()) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			gmssl_secure_clear(outbuf.data(), outbuf.size());
			throw std::runtime_error("GmSSL SM2 decrypt update failed.");
		}

		if (sm2_decrypt_finish(&ctx, &key, outbuf.data(), &outlen) != 1) {
			gmssl_secure_clear(&key, sizeof(key));
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(keybuf.data(), keybuf.size());
			gmssl_secure_clear(outbuf.data(), outbuf.size());
			throw std::runtime_error("GmSSL SM2 decrypt finish failed.");
		}

		uint8_array_t ret(outbuf.begin(), outbuf.begin() + outlen);

		gmssl_secure_clear(&key, sizeof(key));
		gmssl_secure_clear(&ctx, sizeof(ctx));
		gmssl_secure_clear(keybuf.data(), keybuf.size());
		gmssl_secure_clear(outbuf.data(), outbuf.size());

		return std::move(ret);
	}
	uint8_array_t sm3_digest(const uint8_array_t &input_data)
	{
		SM3_DIGEST_CTX ctx;

		if (sm3_digest_init(&ctx, nullptr, 0) != 1) {
			gmssl_secure_clear(&ctx, sizeof(ctx));
			throw std::runtime_error("GmSSL SM3 context init failed.");
		}

		if (sm3_digest_update(&ctx, input_data.data(), input_data.size()) != 1) {
			gmssl_secure_clear(&ctx, sizeof(ctx));
			throw std::runtime_error("GmSSL SM3 update error.");
		}

		uint8_array_t raw_hash(SM3_DIGEST_SIZE);
		if (sm3_digest_finish(&ctx, raw_hash.data()) != 1) {
			gmssl_secure_clear(&ctx, sizeof(ctx));
			throw std::runtime_error("GmSSL SM3 finish failed.");
		}

		gmssl_secure_clear(&ctx, sizeof(ctx));

		return raw_hash;
	}
	enum class sm4_mode : uint8_t {
		cbc_encrypt = 0b00,
		cbc_decrypt = 0b01,
		ctr_encrypt = 0b10,
		ctr_decrypt = 0b11,
	};
	constexpr size_t sm4_key_size = SM4_KEY_SIZE;
	uint8_array_t sm4(sm4_mode action, const std::string &key, const std::string &init_vec, const uint8_array_t &input_bytes)
	{
		if (key.size() != sm4_key_size || init_vec.size() != sm4_key_size)
			throw std::runtime_error("GmSSL SM4 key or iv size error.");

		if (input_bytes.size() == 0)
			throw std::runtime_error("GmSSL SM4 data size invalid.");

		const uint8_t *k = reinterpret_cast<const uint8_t *>(key.data());
		const uint8_t *iv = reinterpret_cast<const uint8_t *>(init_vec.data());

		union {
			SM4_CBC_CTX cbc;
			SM4_CTR_CTX ctr;
		} ctx;

		if (((uint8_t)action & 0b10 ? sm4_ctr_encrypt_init(&ctx.ctr, k, iv) :
		        ((uint8_t)action & 0b01 ? sm4_cbc_decrypt_init(&ctx.cbc, k, iv) :
		         sm4_cbc_encrypt_init(&ctx.cbc, k, iv))) != 1) {
			gmssl_secure_clear(&ctx, sizeof(ctx));
			throw std::runtime_error("GmSSL SM4 context init failed.");
		}

		uint8_array_t output_bytes;
		uint8_array_t buff(buff_size);
		size_t outlen = 0;
		size_t offset = 0;

		while (offset < input_bytes.size()) {
			size_t inlen = offset + buff_size >= input_bytes.size() ? input_bytes.size() - offset : buff_size;
			if (((uint8_t)action & 0b10 ? sm4_ctr_encrypt_update(&ctx.ctr, input_bytes.data() + offset, inlen, buff.data(), &outlen) :
			        ((uint8_t)action & 0b01 ? sm4_cbc_decrypt_update(&ctx.cbc, input_bytes.data() + offset, inlen, buff.data(), &outlen) :
			         sm4_cbc_encrypt_update(&ctx.cbc, input_bytes.data() + offset, inlen, buff.data(), &outlen))) != 1) {
				gmssl_secure_clear(&ctx, sizeof(ctx));
				gmssl_secure_clear(output_bytes.data(), output_bytes.size());
				gmssl_secure_clear(buff.data(), buff_size);
				throw std::runtime_error((uint8_t)action & 0b01 ? "GmSSL SM4 decrypt error." : "GmSSL SM4 encrypt error.");
			}

			if (outlen > 0)
				output_bytes.insert(output_bytes.end(), buff.data(), buff.data() + outlen);

			offset += inlen;
		}

		if (((uint8_t)action & 0b10 ? sm4_ctr_encrypt_finish(&ctx.ctr, buff.data(), &outlen) :
		        ((uint8_t)action & 0b01 ? sm4_cbc_decrypt_finish(&ctx.cbc, buff.data(), &outlen) :
		         sm4_cbc_encrypt_finish(&ctx.cbc, buff.data(), &outlen))) != 1) {
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(output_bytes.data(), output_bytes.size());
			gmssl_secure_clear(buff.data(), buff_size);
			throw std::runtime_error((uint8_t)action & 0b01 ? "GmSSL SM4 decrypt finish failed." : "GmSSL SM4 encrypt finish failed.");
		}

		if (outlen > 0)
			output_bytes.insert(output_bytes.end(), buff.data(), buff.data() + outlen);

		gmssl_secure_clear(&ctx, sizeof(ctx));
		gmssl_secure_clear(buff.data(), buff_size);

		return output_bytes;
	}
	void sm4_stream(sm4_mode action, const std::string &key, const std::string &init_vec, std::istream &is, std::ostream &os)
	{
		if (key.size() != sm4_key_size || init_vec.size() != sm4_key_size)
			throw std::runtime_error("GmSSL SM4 key or iv size error.");

		if (!is || !os)
			throw std::runtime_error("GmSSL SM4 stream not available.");

		const uint8_t *k = reinterpret_cast<const uint8_t *>(key.data());
		const uint8_t *iv = reinterpret_cast<const uint8_t *>(init_vec.data());

		union {
			SM4_CBC_CTX cbc;
			SM4_CTR_CTX ctr;
		} ctx;

		if (((uint8_t)action & 0b10 ? sm4_ctr_encrypt_init(&ctx.ctr, k, iv) :
		        ((uint8_t)action & 0b01 ? sm4_cbc_decrypt_init(&ctx.cbc, k, iv) :
		         sm4_cbc_encrypt_init(&ctx.cbc, k, iv))) != 1) {
			gmssl_secure_clear(&ctx, sizeof(ctx));
			throw std::runtime_error("GmSSL SM4 context init failed.");
		}

		uint8_array_t inbuf(buff_size);
		uint8_array_t outbuf(buff_size);
		size_t outlen = 0;

		while (is) {
			size_t inlen = is.readsome(reinterpret_cast<char *>(inbuf.data()), buff_size);
			if (((uint8_t)action & 0b10 ? sm4_ctr_encrypt_update(&ctx.ctr, inbuf.data(), inlen, outbuf.data(), &outlen) :
			        ((uint8_t)action & 0b01 ? sm4_cbc_decrypt_update(&ctx.cbc, inbuf.data(), inlen, outbuf.data(), &outlen) :
			         sm4_cbc_encrypt_update(&ctx.cbc, inbuf.data(), inlen, outbuf.data(), &outlen))) != 1) {
				gmssl_secure_clear(&ctx, sizeof(ctx));
				gmssl_secure_clear(inbuf.data(), buff_size);
				gmssl_secure_clear(outbuf.data(), buff_size);
				throw std::runtime_error((uint8_t)action & 0b01 ? "GmSSL SM4 decrypt error." : "GmSSL SM4 encrypt error.");
			}

			if (outlen > 0)
				os.write(reinterpret_cast<const char *>(outbuf.data()), outlen);
		}

		if (((uint8_t)action & 0b10 ? sm4_ctr_encrypt_finish(&ctx.ctr, outbuf.data(), &outlen) :
		        ((uint8_t)action & 0b01 ? sm4_cbc_decrypt_finish(&ctx.cbc, outbuf.data(), &outlen) :
		         sm4_cbc_encrypt_finish(&ctx.cbc, outbuf.data(), &outlen))) != 1) {
			gmssl_secure_clear(&ctx, sizeof(ctx));
			gmssl_secure_clear(inbuf.data(), buff_size);
			gmssl_secure_clear(outbuf.data(), buff_size);
			throw std::runtime_error((uint8_t)action & 0b01 ? "GmSSL SM4 decrypt finish failed." : "GmSSL SM4 encrypt finish failed.");
		}

		if (outlen > 0)
			os.write(reinterpret_cast<const char *>(outbuf.data()), outlen);

		gmssl_secure_clear(&ctx, sizeof(ctx));
		gmssl_secure_clear(inbuf.data(), buff_size);
		gmssl_secure_clear(outbuf.data(), buff_size);
	}
}
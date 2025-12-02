#include "gmssl.hpp"

template <>
constexpr const char *cs_impl::get_name_of_type<gmssl::uint8_array_t>()
{
	return "bytes_array";
}

template <>
struct cs_impl::type_conversion_cs<gmssl::uint8_array_t> {
	using source_type = cs::string;
};

template <>
struct cs_impl::type_convertor<cs::string, gmssl::uint8_array_t> {
	static gmssl::uint8_array_t convert(const cs::string &str)
	{
		return gmssl::bytes_encode(str);
	}
};

#if COVSCRIPT_ABI_VERSION >= 251101
template <>
cs::string_borrower cs_impl::to_string<gmssl::uint8_array_t>(const gmssl::uint8_array_t &data)
{
	return gmssl::bytes_decode(data);
}
#else
template <>
std::string cs_impl::to_string<gmssl::uint8_array_t>(const gmssl::uint8_array_t &data)
{
	return gmssl::bytes_decode(data);
}
#endif

CNI_ROOT_NAMESPACE {
	using namespace gmssl;
	CNI(secure_clear)
	CNI(rand_chars)
	CNI_V(rand_bytes, gmssl::rand_bytes)
	CNI_CONST(bytes_encode)
	CNI_CONST(bytes_decode)
	CNI_CONST(hex_encode)
	CNI_CONST(hex_decode)
	CNI_CONST(base64_encode)
	CNI_CONST(base64_decode)
	CNI(sm2_pem_read)
	CNI(sm2_pem_write)
	CNI_VALUE_CONST(pem_name_pbk, "PUBLIC KEY")
	CNI_VALUE_CONST(pem_name_pvk, "EC PRIVATE KEY")
	cs::var sm2_key_generate_impl(const std::string &passwd)
	{
		cs::var pubkey = cs::var::make<uint8_array_t>();
		cs::var privkey = cs::var::make<uint8_array_t>();
		gmssl::sm2_key_generate(pubkey.val<uint8_array_t>(), privkey.val<uint8_array_t>(), passwd);
		return cs::var::make<cs::array>(cs::array({pubkey, privkey}));
	}
	CNI_V(sm2_key_generate, sm2_key_generate_impl)
	CNI_V(sm2_sign, gmssl::sm2_sign)
	CNI_V(sm2_verify, gmssl::sm2_verify)
	CNI_V(sm2_encrypt, gmssl::sm2_encrypt)
	CNI_V(sm2_decrypt, gmssl::sm2_decrypt)
	CNI(sm3)
	CNI(sm3_hmac)
	CNI_V(sm3_pbkdf2, gmssl::sm3_pbkdf2)
	CNI_NAMESPACE(sm4_mode)
	{
		CNI_VALUE_CONST(cbc_encrypt, gmssl::sm4_mode::cbc_encrypt)
		CNI_VALUE_CONST(cbc_decrypt, gmssl::sm4_mode::cbc_decrypt)
		CNI_VALUE_CONST(ctr_encrypt, gmssl::sm4_mode::ctr_encrypt)
		CNI_VALUE_CONST(ctr_decrypt, gmssl::sm4_mode::ctr_decrypt)
	}
	CNI_VALUE_CONST(sm4_key_size, gmssl::sm4_key_size)
	CNI(sm4)
}
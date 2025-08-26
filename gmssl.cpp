#include <covscript/cni.hpp>
#include <covscript/dll.hpp>
#include "gmssl.hpp"

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

void set_stdin_echo(bool enable)
{
#ifdef WIN32
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode;
	GetConsoleMode(hStdin, &mode);

	if (!enable)
		mode &= ~ENABLE_ECHO_INPUT;
	else
		mode |= ENABLE_ECHO_INPUT;

	SetConsoleMode(hStdin, mode);

#else
	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);
	if (!enable)
		tty.c_lflag &= ~ECHO;
	else
		tty.c_lflag |= ECHO;

	(void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

template <>
std::string cs_impl::to_string<gmssl::uint8_array_t>(const gmssl::uint8_array_t &data)
{
	return gmssl::bytes_decode(data);
}

CNI_ROOT_NAMESPACE {
	using namespace gmssl;
	CNI(set_stdin_echo)
	CNI(secure_clear)
	CNI_V(rand_bytes, [](size_t count)
	{
		return gmssl::rand_bytes(count);
	})
	CNI_V(rand_bytes_s, gmssl::rand_bytes)
	CNI_CONST(bytes_encode)
	CNI_CONST(bytes_decode)
	CNI_CONST(hex_encode)
	CNI_CONST(hex_decode)
	CNI_CONST(base64_encode)
	CNI_CONST(base64_decode)
	CNI(sm2_pem_read)
	CNI(sm2_pem_write)
	cs::var sm2_key_generate_impl(const std::string &passwd)
	{
		cs::var pubkey = cs::var::make<uint8_array_t>();
		cs::var privkey = cs::var::make<uint8_array_t>();
		gmssl::sm2_key_generate(pubkey.val<uint8_array_t>(), privkey.val<uint8_array_t>(), passwd);
		return cs::var::make<cs::array>(cs::array({pubkey, privkey}));
	}
	CNI_V(sm2_key_generate, sm2_key_generate_impl)
	CNI_V(sm2_sign, gmssl::sm2_sign)
	CNI(sm2_sign_stream)
	CNI_V(sm2_verify, gmssl::sm2_verify)
	CNI(sm2_verify_stream)
	CNI_V(sm2_encrypt, gmssl::sm2_encrypt)
	CNI_V(sm2_decrypt, gmssl::sm2_decrypt)
	CNI(sm3_digest)
	CNI_NAMESPACE(sm4_mode)
	{
		CNI_VALUE_CONST(cbc_encrypt, gmssl::sm4_mode::cbc_encrypt)
		CNI_VALUE_CONST(cbc_decrypt, gmssl::sm4_mode::cbc_decrypt)
		CNI_VALUE_CONST(ctr_encrypt, gmssl::sm4_mode::ctr_encrypt)
		CNI_VALUE_CONST(ctr_decrypt, gmssl::sm4_mode::ctr_decrypt)
	}
	CNI_VALUE_CONST(sm4_key_size, gmssl::sm4_key_size)
	CNI(sm4)
	CNI(sm4_stream)
}
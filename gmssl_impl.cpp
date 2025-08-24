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

	if( !enable )
		mode &= ~ENABLE_ECHO_INPUT;
	else
		mode |= ENABLE_ECHO_INPUT;

	SetConsoleMode(hStdin, mode );

#else
	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);
	if( !enable )
		tty.c_lflag &= ~ECHO;
	else
		tty.c_lflag |= ECHO;

	(void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

template <>
std::string cs_impl::to_string<gmssl::uint8_array_t>(const gmssl::uint8_array_t &data)
{
	return gmssl::bytes_decode(data);
}

CNI_ROOT_NAMESPACE {
	using namespace gmssl;
	CNI_V(rand_bytes_s, [](size_t count)
	{
		return gmssl::rand_bytes(count);
	})
	CNI_V(rand_bytes_v, gmssl::rand_bytes)
	CNI(set_stdin_echo)
	CNI_CONST(bytes_encode)
	CNI_CONST(bytes_decode)
	CNI_CONST(hex_encode)
	CNI_CONST(hex_decode)
	CNI_CONST(base64_encode)
	CNI_CONST(base64_decode)
	CNI(sm3_digest)
	CNI_NAMESPACE(sm4_mode)
	{
		CNI_VALUE_CONST(cbc_encrypt, gmssl::sm4_mode::cbc_encrypt)
		CNI_VALUE_CONST(cbc_decrypt, gmssl::sm4_mode::cbc_decrypt)
		CNI_VALUE_CONST(ctr_encrypt, gmssl::sm4_mode::ctr_encrypt)
		CNI_VALUE_CONST(ctr_decrypt, gmssl::sm4_mode::ctr_decrypt)
	}
	CNI_VALUE_CONST(sm4_key_size, gmssl::sm4_key_size)
	CNI_V(sm4_s, [](gmssl::sm4_mode action, const std::string &key, const std::string &init_vec, const uint8_array_t &input_bytes)
	{
		return gmssl::sm4(action, key, init_vec, input_bytes);
	})
	CNI_V(sm4_v, gmssl::sm4)
}
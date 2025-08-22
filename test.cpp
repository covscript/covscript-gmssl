#include "gmssl.hpp"
#include <iostream>

int main()
{
	std::string input;
	std::string key = "covscript1234567", iv = gmssl::rand_bytes(gmssl::sm4_key_size, 2333);
    std::cout << "SM4 IV = " << iv << std::endl;
	while (std::getline(std::cin, input)) {
		gmssl::uint8_array_t input_bytes = gmssl::bytes_encode(input);
		std::cout << "SM3 Digest: " << gmssl::bytes_decode(gmssl::hex_encode(gmssl::sm3_digest(input_bytes))) << std::endl;
		gmssl::uint8_array_t cbc_encrypted = gmssl::sm4(gmssl::sm4_mode::cbc_encrypt, key, iv, gmssl::base64_encode(input_bytes));
		std::cout << "SM4 CBC encrypted: " << gmssl::bytes_decode(gmssl::hex_encode(cbc_encrypted)) << std::endl;
		std::cout << "SM4 CBC decrypted: " << gmssl::bytes_decode(gmssl::base64_decode(gmssl::sm4(gmssl::sm4_mode::cbc_decrypt, key, iv, cbc_encrypted))) << std::endl;
	}
	return 0;
}

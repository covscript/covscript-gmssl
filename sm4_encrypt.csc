import gmssl

var key = null
gmssl.set_stdin_echo(false)
loop
    system.out.print("Please set password: ")
    key = system.in.getline()
    if key.size < 6
        system.out.println("\nPassword must have 6 characters.")
        continue
    end
    system.out.print("\nRepeat password: ")
    if system.in.getline() != key
        system.out.println("\nPassword not match.")
        continue
    else
        system.out.print("\n")
        break
    end
end
gmssl.set_stdin_echo(true)
key = gmssl.sm3_pbkdf2(key, "covscript", 5, gmssl.sm4_key_size)

var iv = gmssl.rand_chars(gmssl.sm4_key_size, 2333)
system.out.println("SM4 IV: " + iv)

while system.in.good()
    system.out.print("Data: ")
    var input_bytes = system.in.getline()
    system.out.println("SM3 Digest: " + gmssl.hex_encode(gmssl.sm3(input_bytes)))
    system.out.println("SM3 HMAC Digest: " + gmssl.hex_encode(gmssl.sm3_hmac(key, input_bytes)))

    var ctr_encrypted = gmssl.sm4(gmssl.sm4_mode.ctr_encrypt, key, iv, gmssl.base64_encode(input_bytes))
    system.out.println("SM4 CTR encrypted: " + gmssl.hex_encode(ctr_encrypted))
    system.out.println("SM4 CTR decrypted: " + gmssl.base64_decode(gmssl.sm4(gmssl.sm4_mode.ctr_decrypt, key, iv, ctr_encrypted)))

    var cbc_encrypted = gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, key, iv, gmssl.base64_encode(input_bytes))
    system.out.println("SM4 CBC encrypted: " + gmssl.hex_encode(cbc_encrypted))
    system.out.println("SM4 CBC decrypted: " + gmssl.base64_decode(gmssl.sm4(gmssl.sm4_mode.cbc_decrypt, key, iv, cbc_encrypted)))
end

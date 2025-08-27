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

var (pubkey, privkey) = gmssl.sm2_key_generate(key)

system.out.println("SM2 Public Key: " + gmssl.hex_encode(pubkey))
system.out.println("SM2 Private Key: " + gmssl.hex_encode(privkey))

var id = "covscript.org.cn"

while system.in.good()
    system.out.print("Data: ")
    var input_bytes = gmssl.bytes_encode(system.in.getline())
    system.out.println("SM3 digest: " + gmssl.hex_encode(gmssl.sm3(input_bytes)))
    system.out.println("SM2 signature: " + gmssl.hex_encode(gmssl.sm2_sign(privkey, key, id, input_bytes)))
    var sm2_encrypted = gmssl.sm2_encrypt(pubkey, gmssl.base64_encode(input_bytes))
    system.out.println("SM2 encrypted: " + gmssl.hex_encode(sm2_encrypted))
    system.out.println("SM2 decrypted: " + gmssl.base64_decode(gmssl.sm2_decrypt(privkey, key, sm2_encrypted)))
end

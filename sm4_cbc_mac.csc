import gmssl

var key = null
system.console.echo(false)
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
system.console.echo(true)
key = gmssl.sm3_pbkdf2(key, gmssl.bytes_encode("covscript"), gmssl.sm3_pbkdf2_min_iter, gmssl.sm4_key_size)

while system.in.good()
    system.out.print("Data: ")
    var input_bytes = system.in.getline()
    system.out.println("SM3 Digest: " + gmssl.hex_encode(gmssl.sm3(input_bytes)))
    system.out.println("SM3 HMAC: " + gmssl.hex_encode(gmssl.sm3_hmac(key, input_bytes)))
    system.out.println("SM4 CBC-MAC: " + gmssl.hex_encode(gmssl.sm4_cbc_mac(key, gmssl.base64_encode(input_bytes))))
end

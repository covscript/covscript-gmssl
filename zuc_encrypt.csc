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
key = gmssl.sm3_pbkdf2(key, gmssl.bytes_encode("covscript"), gmssl.sm3_pbkdf2_min_iter, gmssl.zuc_key_size)

var iv = gmssl.rand_bytes(gmssl.zuc_iv_size)
system.out.println("ZUC IV: " + gmssl.hex_encode(iv))

while system.in.good()
    system.out.print("Data: ")
    var input_bytes = system.in.getline()
    system.out.println("SM3 Digest: " + gmssl.hex_encode(gmssl.sm3(input_bytes)))

    var encrypted = gmssl.zuc_encrypt(key, iv, gmssl.base64_encode(input_bytes))
    system.out.println("ZUC encrypted: " + gmssl.hex_encode(encrypted))

    var decrypted = gmssl.base64_decode(gmssl.zuc_encrypt(key, iv, encrypted))
    system.out.println("ZUC decrypted: " + decrypted)
end

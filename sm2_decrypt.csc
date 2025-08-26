import gmssl

var key = null
gmssl.set_stdin_echo(false)
loop
    system.out.print("Password: ")
    key = system.in.getline()
    if key.size < 6
        system.out.println("\nPassword must have 6 characters.")
        continue
    else
        system.out.print("\n")
        break
    end
end
gmssl.set_stdin_echo(true)

system.out.print("SM2 Private Key: ")
var privkey = gmssl.hex_decode(gmssl.bytes_encode(system.in.getline()))

while system.in.good()
    system.out.print("Data in Hex: ")
    var raw_data = system.in.getline()
    var bytes_data = gmssl.hex_decode(gmssl.bytes_encode(raw_data))
    var decrypted = gmssl.base64_decode(gmssl.sm2_decrypt(privkey, key, bytes_data))
    system.out.println("SM2 decrypted: " + decrypted)
    system.out.println("SM3 Digest: " + gmssl.hex_encode(gmssl.sm3_digest(decrypted)))
end

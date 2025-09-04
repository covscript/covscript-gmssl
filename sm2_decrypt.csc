import gmssl

var key = null
system.console.echo(false)
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
system.console.echo(true)

system.out.print("SM2 Public Key (Optional, for signature verification): ")
var pubkey = system.in.getline()
if pubkey.size > 0
    pubkey = gmssl.hex_decode(gmssl.bytes_encode(pubkey))
else
    pubkey = null
end

system.out.print("SM2 Private Key: ")
var privkey = gmssl.hex_decode(gmssl.bytes_encode(system.in.getline()))

var id = "covscript.org.cn"

while system.in.good()
    system.out.print("Data in Hex: ")
    var raw_data = system.in.getline()
    var sig = null
    if pubkey != null
        system.out.print("Signature of Data (Optional): ")
        sig = system.in.getline()
        if !sig.empty()
            sig = gmssl.hex_decode(gmssl.bytes_encode(sig))
        else
            sig = null
        end
    end
    var bytes_data = gmssl.hex_decode(gmssl.bytes_encode(raw_data))
    var decrypted = gmssl.base64_decode(gmssl.sm2_decrypt(privkey, key, bytes_data))
    system.out.println("SM2 decrypted: " + decrypted)
    if sig != null
        system.out.println("SM2 signature verified: " + gmssl.sm2_verify(pubkey, sig, id, decrypted))
    end
    system.out.println("SM3 digest: " + gmssl.hex_encode(gmssl.sm3(decrypted)))
end

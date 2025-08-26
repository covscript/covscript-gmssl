import gmssl

var text2mode_map = {"cbc": gmssl.sm4_mode.cbc_decrypt, "ctr": gmssl.sm4_mode.ctr_decrypt}.to_hash_map()
var seed = 2333

var key = null
gmssl.set_stdin_echo(false)
loop
    system.out.print("Password: ")
    key = system.in.getline()
    if key.size != gmssl.sm4_key_size
        system.out.println("\nPassword must have " + gmssl.sm4_key_size + " characters.")
        continue
    else
        system.out.print("\n")
        break
    end
end
gmssl.set_stdin_echo(true)

system.out.print("SM4 IV: ")
var iv = system.in.getline()
if iv.empty()
    iv = gmssl.rand_bytes_s(gmssl.sm4_key_size, seed)
    system.out.println("Set to default IV: " + iv)
end

while system.in.good()
    system.out.print("Data in Hex: ")
    var raw_data = system.in.getline()
    system.out.print("SM4 Mode: ")
    var mode = system.in.getline().tolower()
    if mode.empty()
        system.out.println("Use default mode: CBC")
        mode = "cbc"
    end
    if !text2mode_map.exist(mode)
        system.out.println("SM4 Mode \"" + mode.toupper() + "\" not supported.")
        continue
    end
    mode = text2mode_map.at(mode)
    var bytes_data = gmssl.hex_decode(gmssl.bytes_encode(raw_data))
    var decrypted = gmssl.base64_decode(gmssl.sm4(mode, key, iv, bytes_data))
    system.out.println("SM4 CBC decrypted: " + decrypted)
    system.out.println("SM3 Digest: " + gmssl.hex_encode(gmssl.sm3_digest(decrypted)))
end

import gmssl

var key = "covscript1234567"
var seed = 2333
var iv = gmssl.rand_bytes(gmssl.sm4_key_size, seed)
system.out.println("SM4 IV = " + iv)

while system.in.good()
    var input_bytes = gmssl.bytes_encode(system.in.getline())
    system.out.println("SM3 Digest: " + gmssl.hex_encode(gmssl.sm3_digest(input_bytes)))
    
    var ctr_encrypted = gmssl.sm4(gmssl.sm4_mode.ctr_encrypt, key, iv, gmssl.base64_encode(input_bytes))
    system.out.println("SM4 CTR encrypted: " + gmssl.hex_encode(ctr_encrypted))
    system.out.println("SM4 CTR decrypted: " + gmssl.base64_decode(gmssl.sm4(gmssl.sm4_mode.ctr_decrypt, key, iv, ctr_encrypted)))

    var cbc_encrypted = gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, key, iv, gmssl.base64_encode(input_bytes))
    system.out.println("SM4 CBC encrypted: " + gmssl.hex_encode(cbc_encrypted))
    system.out.println("SM4 CBC decrypted: " + gmssl.base64_decode(gmssl.sm4(gmssl.sm4_mode.cbc_decrypt, key, iv, cbc_encrypted)))
end
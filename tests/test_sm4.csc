import gmssl

var _pass = 0
var _fail = 0
var _section = ""

function section(name)
    _section = name
    system.out.println("")
    system.out.println("=== " + name + " ===")
end

function check(label, ok)
    if ok
        system.out.println("[PASS] " + _section + " | " + label)
        _pass += 1
    else
        system.out.println("[FAIL] " + _section + " | " + label)
        _fail += 1
    end
end

function check_eq(label, a, b)
    check(label, a == b)
end

var passwd = "test_sm4_password"
var key = gmssl.sm3_pbkdf2(passwd, gmssl.bytes_encode("covscript"), gmssl.sm3_pbkdf2_min_iter, gmssl.sm4_key_size)
var iv = gmssl.rand_bytes(gmssl.sm4_key_size)
var plaintext = gmssl.bytes_encode("Hello, SM4 Encryption Test!")

section("SM4 CBC encrypt / decrypt")

var cbc_enc = gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, key, iv, plaintext)
check("M01: CBC ciphertext not empty", cbc_enc.size > 0)
check("M02: CBC ciphertext != plaintext", cbc_enc != plaintext)

var cbc_dec = gmssl.sm4(gmssl.sm4_mode.cbc_decrypt, key, iv, cbc_enc)
check_eq("M03: CBC decrypt round-trip", gmssl.bytes_decode(cbc_dec), "Hello, SM4 Encryption Test!")

section("SM4 CTR encrypt / decrypt")

var ctr_enc = gmssl.sm4(gmssl.sm4_mode.ctr_encrypt, key, iv, plaintext)
check("M04: CTR ciphertext not empty", ctr_enc.size > 0)
check("M05: CTR ciphertext != plaintext", ctr_enc != plaintext)

var ctr_dec = gmssl.sm4(gmssl.sm4_mode.ctr_decrypt, key, iv, ctr_enc)
check_eq("M06: CTR decrypt round-trip", gmssl.bytes_decode(ctr_dec), "Hello, SM4 Encryption Test!")

section("SM4 different inputs")

var key2 = gmssl.sm3_pbkdf2("different_password", gmssl.bytes_encode("covscript"), gmssl.sm3_pbkdf2_min_iter, gmssl.sm4_key_size)
var cbc_enc2 = gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, key2, iv, plaintext)
check("M07: different key different ciphertext", gmssl.hex_encode(cbc_enc) != gmssl.hex_encode(cbc_enc2))

var iv2 = gmssl.rand_bytes(gmssl.sm4_key_size)
var cbc_enc3 = gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, key, iv2, plaintext)
check("M08: different IV different ciphertext", gmssl.hex_encode(cbc_enc) != gmssl.hex_encode(cbc_enc3))

section("SM4 CBC-MAC")

var mac1 = gmssl.sm4_cbc_mac(key, plaintext)
check_eq("M09: CBC-MAC returns 16 bytes", mac1.size, gmssl.sm4_cbc_mac_size)

var mac2 = gmssl.sm4_cbc_mac(key, plaintext)
check_eq("M10: CBC-MAC deterministic", gmssl.hex_encode(mac1), gmssl.hex_encode(mac2))

var mac3 = gmssl.sm4_cbc_mac(key, gmssl.bytes_encode("different data"))
check("M11: CBC-MAC different data different MAC", gmssl.hex_encode(mac1) != gmssl.hex_encode(mac3))

section("SM4 constants")

check_eq("M12: sm4_key_size", gmssl.sm4_key_size, 16)
check_eq("M13: sm4_cbc_mac_size", gmssl.sm4_cbc_mac_size, 16)

system.out.println("")
system.out.println("=== Results ===")
system.out.println("PASS: " + _pass)
system.out.println("FAIL: " + _fail)
if _fail > 0
    system.exit(1)
end

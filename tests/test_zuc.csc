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

function to_hex(bytes)
    return gmssl.bytes_decode(gmssl.hex_encode(bytes))
end

var passwd = "test_zuc_password"
var key = gmssl.sm3_pbkdf2(passwd, gmssl.bytes_encode("covscript"), gmssl.sm3_pbkdf2_min_iter, gmssl.zuc_key_size)
var iv = gmssl.rand_bytes(gmssl.zuc_iv_size)
var plaintext = gmssl.bytes_encode("Hello, ZUC Stream Cipher!")

section("ZUC encrypt / decrypt")

var encrypted = gmssl.zuc_encrypt(key, iv, plaintext)
check("Z01: ciphertext produced", encrypted != null)
check("Z02: ciphertext != plaintext", encrypted != plaintext)

var decrypted = gmssl.zuc_encrypt(key, iv, encrypted)
check_eq("Z03: decrypt round-trip", gmssl.bytes_decode(decrypted), "Hello, ZUC Stream Cipher!")

section("ZUC different inputs")

var key2 = gmssl.sm3_pbkdf2("different_password", gmssl.bytes_encode("covscript"), gmssl.sm3_pbkdf2_min_iter, gmssl.zuc_key_size)
var enc2 = gmssl.zuc_encrypt(key2, iv, plaintext)
check("Z04: different key different ciphertext", to_hex(encrypted) != to_hex(enc2))

var iv2 = gmssl.rand_bytes(gmssl.zuc_iv_size)
var enc3 = gmssl.zuc_encrypt(key, iv2, plaintext)
check("Z05: different IV different ciphertext", to_hex(encrypted) != to_hex(enc3))

section("ZUC deterministic")

var enc4 = gmssl.zuc_encrypt(key, iv, plaintext)
check_eq("Z06: deterministic", to_hex(encrypted), to_hex(enc4))

section("ZUC constants")

check_eq("Z07: zuc_key_size", gmssl.zuc_key_size, 16)
check_eq("Z08: zuc_iv_size", gmssl.zuc_iv_size, 16)

system.out.println("")
system.out.println("=== Results ===")
system.out.println("PASS: " + _pass)
system.out.println("FAIL: " + _fail)
if _fail > 0
    system.exit(1)
end

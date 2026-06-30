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

var passwd = "test_password_123"
var (pubkey, privkey) = gmssl.sm2_key_generate(passwd)

section("SM2 key generation")

check("S01: pubkey not empty", pubkey.size > 0)
check("S02: privkey not empty", privkey.size > 0)
check("S03: pubkey != privkey", pubkey != privkey)

var id = "covscript.org.cn"
var data = gmssl.bytes_encode("Hello, SM2!")

section("SM2 sign / verify")

var sig = gmssl.sm2_sign(privkey, passwd, id, data)
check("S04: signature not empty", sig.size > 0)
check("S05: signature size <= max", sig.size <= gmssl.sm2_max_signature_size)

var ok = gmssl.sm2_verify(pubkey, sig, id, data)
check("S06: verify succeeds with correct key", ok)

var data2 = gmssl.bytes_encode("Different data")
var ok2 = gmssl.sm2_verify(pubkey, sig, id, data2)
check("S07: verify fails with different data", !ok2)

section("SM2 encrypt / decrypt")

var plaintext = gmssl.bytes_encode("Hello, SM2 Encryption!")
var ciphertext = gmssl.sm2_encrypt(pubkey, plaintext)
check("S08: ciphertext not empty", ciphertext.size > 0)
check("S09: ciphertext size <= max", ciphertext.size <= gmssl.sm2_max_ciphertext_size)
check("S10: ciphertext != plaintext", ciphertext != plaintext)

var decrypted = gmssl.sm2_decrypt(privkey, passwd, ciphertext)
check_eq("S11: decrypt round-trip", gmssl.bytes_decode(decrypted), "Hello, SM2 Encryption!")

section("SM2 ECDH")

var passwd2 = "another_password_456"
var (pubkey2, privkey2) = gmssl.sm2_key_generate(passwd2)

var shared1 = gmssl.sm2_ecdh(privkey, passwd, pubkey2)
var shared2 = gmssl.sm2_ecdh(privkey2, passwd2, pubkey)
check_eq("S12: ECDH shared secret size", shared1.size, gmssl.ecdh_shared_key_size)
check_eq("S13: ECDH shared secrets match", gmssl.hex_encode(shared1), gmssl.hex_encode(shared2))

section("SM2 constants")

check_eq("S14: sm2_max_signature_size", gmssl.sm2_max_signature_size, 72)
check_eq("S15: sm2_max_plaintext_size", gmssl.sm2_max_plaintext_size, 255)
check_eq("S16: sm2_max_ciphertext_size", gmssl.sm2_max_ciphertext_size, 366)
check_eq("S17: ecdh_shared_key_size", gmssl.ecdh_shared_key_size, 32)

system.out.println("")
system.out.println("=== Results ===")
system.out.println("PASS: " + _pass)
system.out.println("FAIL: " + _fail)
if _fail > 0
    system.exit(1)
end

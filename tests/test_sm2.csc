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

function hex_str(bytes)
    return gmssl.bytes_decode(gmssl.hex_encode(bytes))
end

var passwd = "test_password_123"
var (pubkey, privkey) = gmssl.sm2_key_generate(passwd)

section("SM2 key generation")

check("S01: pubkey not empty", pubkey != null)
check("S02: privkey not empty", privkey != null)

var id = "covscript.org.cn"
var data = gmssl.bytes_encode("Hello, SM2!")

section("SM2 sign / verify")

var sig = gmssl.sm2_sign(privkey, passwd, id, data)
check("S03: signature produced", sig != null)

var ok = gmssl.sm2_verify(pubkey, sig, id, data)
check("S04: verify succeeds with correct key", ok)

var verify_failed = false
try
    var data2 = gmssl.bytes_encode("Different data")
    gmssl.sm2_verify(pubkey, sig, id, data2)
catch e
    verify_failed = true
end
check("S05: verify fails with different data", verify_failed)

section("SM2 encrypt / decrypt")

var plaintext = gmssl.bytes_encode("Hello, SM2 Encryption!")
var ciphertext = gmssl.sm2_encrypt(pubkey, plaintext)
check("S06: ciphertext produced", ciphertext != null)
check("S07: ciphertext != plaintext", ciphertext != plaintext)

var decrypted = gmssl.sm2_decrypt(privkey, passwd, ciphertext)
check_eq("S08: decrypt round-trip", gmssl.bytes_decode(decrypted), "Hello, SM2 Encryption!")

section("SM2 ECDH")

var passwd2 = "another_password_456"
var (pubkey2, privkey2) = gmssl.sm2_key_generate(passwd2)

var shared1 = gmssl.sm2_ecdh(privkey, passwd, pubkey2)
var shared2 = gmssl.sm2_ecdh(privkey2, passwd2, pubkey)
check_eq("S09: ECDH shared secrets match", hex_str(shared1), hex_str(shared2))

section("SM2 constants")

check_eq("S10: sm2_max_signature_size", gmssl.sm2_max_signature_size, 72)
check_eq("S11: sm2_max_plaintext_size", gmssl.sm2_max_plaintext_size, 255)
check_eq("S12: sm2_max_ciphertext_size", gmssl.sm2_max_ciphertext_size, 366)
check_eq("S13: ecdh_shared_key_size", gmssl.ecdh_shared_key_size, 32)

system.out.println("")
system.out.println("=== Results ===")
system.out.println("PASS: " + _pass)
system.out.println("FAIL: " + _fail)
if _fail > 0
    system.exit(1)
end

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

section("SM3 hash")

var h1 = gmssl.sm3(gmssl.bytes_encode("abc"))
check_eq("H01: sm3 returns 32 bytes", h1.size, gmssl.sm3_digest_size)
check_eq("H02: sm3 hash length is 32", h1.size, 32)

var h2 = gmssl.sm3(gmssl.bytes_encode("abc"))
check_eq("H03: sm3 deterministic", gmssl.hex_encode(h1), gmssl.hex_encode(h2))

var h3 = gmssl.sm3(gmssl.bytes_encode("abcd"))
check("H04: sm3 different input different hash", gmssl.hex_encode(h1) != gmssl.hex_encode(h3))

section("SM3 HMAC")

var key = gmssl.sm3_pbkdf2("test", gmssl.bytes_encode("salt"), gmssl.sm3_pbkdf2_min_iter, gmssl.sm4_key_size)
var mac1 = gmssl.sm3_hmac(key, gmssl.bytes_encode("hello"))
check_eq("H05: sm3_hmac returns 32 bytes", mac1.size, gmssl.sm3_digest_size)

var mac2 = gmssl.sm3_hmac(key, gmssl.bytes_encode("hello"))
check_eq("H06: sm3_hmac deterministic", gmssl.hex_encode(mac1), gmssl.hex_encode(mac2))

var mac3 = gmssl.sm3_hmac(key, gmssl.bytes_encode("world"))
check("H07: sm3_hmac different data different mac", gmssl.hex_encode(mac1) != gmssl.hex_encode(mac3))

section("SM3 PBKDF2")

var dk1 = gmssl.sm3_pbkdf2("password", gmssl.bytes_encode("salt"), gmssl.sm3_pbkdf2_min_iter, 32)
check_eq("H08: sm3_pbkdf2 returns requested length", dk1.size, 32)

var dk2 = gmssl.sm3_pbkdf2("password", gmssl.bytes_encode("salt"), gmssl.sm3_pbkdf2_min_iter, 32)
check_eq("H09: sm3_pbkdf2 deterministic", gmssl.hex_encode(dk1), gmssl.hex_encode(dk2))

var dk3 = gmssl.sm3_pbkdf2("password", gmssl.bytes_encode("salt"), gmssl.sm3_pbkdf2_min_iter, 16)
check_eq("H10: sm3_pbkdf2 different outlen", dk3.size, 16)

var dk4 = gmssl.sm3_pbkdf2("password", gmssl.bytes_encode("salt"), gmssl.sm3_pbkdf2_min_iter + 1, 32)
check("H11: sm3_pbkdf2 different iter different key", gmssl.hex_encode(dk1) != gmssl.hex_encode(dk4))

section("SM3 PBKDF2 constants")

check_eq("H12: sm3_pbkdf2_min_iter is 10000", gmssl.sm3_pbkdf2_min_iter, 10000)
check("H13: sm3_pbkdf2_max_iter > min_iter", gmssl.sm3_pbkdf2_max_iter > gmssl.sm3_pbkdf2_min_iter)
check_eq("H14: sm3_pbkdf2_max_salt_size is 64", gmssl.sm3_pbkdf2_max_salt_size, 64)

system.out.println("")
system.out.println("=== Results ===")
system.out.println("PASS: " + _pass)
system.out.println("FAIL: " + _fail)
if _fail > 0
    system.exit(1)
end

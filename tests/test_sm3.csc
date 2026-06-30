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

section("SM3 hash")

var h1 = gmssl.sm3(gmssl.bytes_encode("abc"))
var h1_hex = to_hex(h1)
check_eq("H01: sm3 hash length is 64 hex chars", h1_hex.size, 64)

var h2 = gmssl.sm3(gmssl.bytes_encode("abc"))
check_eq("H02: sm3 deterministic", to_hex(h1), to_hex(h2))

var h3 = gmssl.sm3(gmssl.bytes_encode("abcd"))
check("H03: sm3 different input different hash", to_hex(h1) != to_hex(h3))

section("SM3 HMAC")

var key = gmssl.sm3_pbkdf2("test", gmssl.bytes_encode("salt"), gmssl.sm3_pbkdf2_min_iter, gmssl.sm4_key_size)
var mac1 = gmssl.sm3_hmac(key, gmssl.bytes_encode("hello"))
check_eq("H04: sm3_hmac hash length is 64 hex chars", to_hex(mac1).size, 64)

var mac2 = gmssl.sm3_hmac(key, gmssl.bytes_encode("hello"))
check_eq("H05: sm3_hmac deterministic", to_hex(mac1), to_hex(mac2))

var mac3 = gmssl.sm3_hmac(key, gmssl.bytes_encode("world"))
check("H06: sm3_hmac different data different mac", to_hex(mac1) != to_hex(mac3))

section("SM3 PBKDF2")

var dk1 = gmssl.sm3_pbkdf2("password", gmssl.bytes_encode("salt"), gmssl.sm3_pbkdf2_min_iter, 32)
check_eq("H07: sm3_pbkdf2 output length", to_hex(dk1).size, 64)

var dk2 = gmssl.sm3_pbkdf2("password", gmssl.bytes_encode("salt"), gmssl.sm3_pbkdf2_min_iter, 32)
check_eq("H08: sm3_pbkdf2 deterministic", to_hex(dk1), to_hex(dk2))

var dk3 = gmssl.sm3_pbkdf2("password", gmssl.bytes_encode("salt"), gmssl.sm3_pbkdf2_min_iter, 16)
check_eq("H09: sm3_pbkdf2 different outlen", to_hex(dk3).size, 32)

var dk4 = gmssl.sm3_pbkdf2("password", gmssl.bytes_encode("salt"), gmssl.sm3_pbkdf2_min_iter + 1, 32)
check("H10: sm3_pbkdf2 different iter different key", to_hex(dk1) != to_hex(dk4))

section("SM3 PBKDF2 constants")

check_eq("H11: sm3_pbkdf2_min_iter is 10000", gmssl.sm3_pbkdf2_min_iter, 10000)
check("H12: sm3_pbkdf2_max_iter > min_iter", gmssl.sm3_pbkdf2_max_iter > gmssl.sm3_pbkdf2_min_iter)
check_eq("H13: sm3_pbkdf2_max_salt_size is 64", gmssl.sm3_pbkdf2_max_salt_size, 64)

system.out.println("")
system.out.println("=== Results ===")
system.out.println("PASS: " + _pass)
system.out.println("FAIL: " + _fail)
if _fail > 0
    system.exit(1)
end

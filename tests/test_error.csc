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

function expect_error(label, fn)
    try
        fn()
        check(label, false)
    catch e
        check(label, true)
    end
end

section("SM3 PBKDF2 errors")

expect_error("E01: PBKDF2 iter below min", function()
    gmssl.sm3_pbkdf2("pass", gmssl.bytes_encode("salt"), 1, 16)
end)

expect_error("E02: PBKDF2 empty salt", function()
    gmssl.sm3_pbkdf2("pass", gmssl.bytes_encode(""), gmssl.sm3_pbkdf2_min_iter, 16)
end)

section("SM2 sign errors")

expect_error("E03: sign empty privkey", function()
    gmssl.sm2_sign(gmssl.bytes_encode(""), "pass", "id", gmssl.bytes_encode("data"))
end)

expect_error("E04: sign empty data", function()
    var (_, privkey) = gmssl.sm2_key_generate("testpass")
    gmssl.sm2_sign(privkey, "testpass", "id", gmssl.bytes_encode(""))
end)

section("SM2 verify errors")

expect_error("E05: verify empty pubkey", function()
    gmssl.sm2_verify(gmssl.bytes_encode(""), gmssl.bytes_encode("sig"), "id", gmssl.bytes_encode("data"))
end)

section("SM2 encrypt errors")

expect_error("E06: encrypt empty pubkey", function()
    gmssl.sm2_encrypt(gmssl.bytes_encode(""), gmssl.bytes_encode("data"))
end)

expect_error("E07: encrypt empty data", function()
    var (pubkey, _) = gmssl.sm2_key_generate("testpass")
    gmssl.sm2_encrypt(pubkey, gmssl.bytes_encode(""))
end)

expect_error("E08: encrypt data too large", function()
    var (pubkey, _) = gmssl.sm2_key_generate("testpass")
    var big_data = gmssl.bytes_encode("")
    var i = 0
    while i < 300
        big_data.append(gmssl.bytes_encode("X"))
        i += 1
    end
    gmssl.sm2_encrypt(pubkey, big_data)
end)

section("SM4 errors")

expect_error("E09: SM4 wrong key size", function()
    gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, gmssl.bytes_encode("short"), gmssl.rand_bytes(16), gmssl.bytes_encode("data"))
end)

expect_error("E10: SM4 wrong IV size", function()
    gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, gmssl.rand_bytes(16), gmssl.bytes_encode("short"), gmssl.bytes_encode("data"))
end)

expect_error("E11: SM4 empty data", function()
    gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, gmssl.rand_bytes(16), gmssl.rand_bytes(16), gmssl.bytes_encode(""))
end)

section("SM4 CBC-MAC errors")

expect_error("E12: CBC-MAC wrong key size", function()
    gmssl.sm4_cbc_mac(gmssl.bytes_encode("short"), gmssl.bytes_encode("data"))
end)

section("ZUC errors")

expect_error("E13: ZUC wrong key size", function()
    gmssl.zuc_encrypt(gmssl.bytes_encode("short"), gmssl.rand_bytes(16), gmssl.bytes_encode("data"))
end)

expect_error("E14: ZUC wrong IV size", function()
    gmssl.zuc_encrypt(gmssl.rand_bytes(16), gmssl.bytes_encode("short"), gmssl.bytes_encode("data"))
end)

system.out.println("")
system.out.println("=== Results ===")
system.out.println("PASS: " + _pass)
system.out.println("FAIL: " + _fail)
if _fail > 0
    system.exit(1)
end

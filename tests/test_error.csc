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

section("SM3 PBKDF2 errors")

try
    gmssl.sm3_pbkdf2("pass", gmssl.bytes_encode("salt"), 1, 16)
    check("E01: PBKDF2 iter below min", false)
catch e
    check("E01: PBKDF2 iter below min", true)
end

try
    gmssl.sm3_pbkdf2("pass", gmssl.bytes_encode(""), gmssl.sm3_pbkdf2_min_iter, 16)
    check("E02: PBKDF2 empty salt", false)
catch e
    check("E02: PBKDF2 empty salt", true)
end

section("SM2 sign errors")

try
    gmssl.sm2_sign(gmssl.bytes_encode(""), "pass", "id", gmssl.bytes_encode("data"))
    check("E03: sign empty privkey", false)
catch e
    check("E03: sign empty privkey", true)
end

try
    var (_, privkey) = gmssl.sm2_key_generate("testpass")
    gmssl.sm2_sign(privkey, "testpass", "id", gmssl.bytes_encode(""))
    check("E04: sign empty data", false)
catch e
    check("E04: sign empty data", true)
end

section("SM2 verify errors")

try
    gmssl.sm2_verify(gmssl.bytes_encode(""), gmssl.bytes_encode("sig"), "id", gmssl.bytes_encode("data"))
    check("E05: verify empty pubkey", false)
catch e
    check("E05: verify empty pubkey", true)
end

section("SM2 encrypt errors")

try
    gmssl.sm2_encrypt(gmssl.bytes_encode(""), gmssl.bytes_encode("data"))
    check("E06: encrypt empty pubkey", false)
catch e
    check("E06: encrypt empty pubkey", true)
end

try
    var (pubkey, _) = gmssl.sm2_key_generate("testpass")
    gmssl.sm2_encrypt(pubkey, gmssl.bytes_encode(""))
    check("E07: encrypt empty data", false)
catch e
    check("E07: encrypt empty data", true)
end

section("SM4 errors")

try
    gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, gmssl.bytes_encode("short"), gmssl.rand_bytes(16), gmssl.bytes_encode("data"))
    check("E08: SM4 wrong key size", false)
catch e
    check("E08: SM4 wrong key size", true)
end

try
    gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, gmssl.rand_bytes(16), gmssl.bytes_encode("short"), gmssl.bytes_encode("data"))
    check("E09: SM4 wrong IV size", false)
catch e
    check("E09: SM4 wrong IV size", true)
end

try
    gmssl.sm4(gmssl.sm4_mode.cbc_encrypt, gmssl.rand_bytes(16), gmssl.rand_bytes(16), gmssl.bytes_encode(""))
    check("E10: SM4 empty data", false)
catch e
    check("E10: SM4 empty data", true)
end

section("SM4 CBC-MAC errors")

try
    gmssl.sm4_cbc_mac(gmssl.bytes_encode("short"), gmssl.bytes_encode("data"))
    check("E11: CBC-MAC wrong key size", false)
catch e
    check("E11: CBC-MAC wrong key size", true)
end

section("ZUC errors")

try
    gmssl.zuc_encrypt(gmssl.bytes_encode("short"), gmssl.rand_bytes(16), gmssl.bytes_encode("data"))
    check("E12: ZUC wrong key size", false)
catch e
    check("E12: ZUC wrong key size", true)
end

try
    gmssl.zuc_encrypt(gmssl.rand_bytes(16), gmssl.bytes_encode("short"), gmssl.bytes_encode("data"))
    check("E13: ZUC wrong IV size", false)
catch e
    check("E13: ZUC wrong IV size", true)
end

system.out.println("")
system.out.println("=== Results ===")
system.out.println("PASS: " + _pass)
system.out.println("FAIL: " + _fail)
if _fail > 0
    system.exit(1)
end

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

section("bytes_encode / bytes_decode")

var original = "Hello, GmSSL!"
var encoded = gmssl.bytes_encode(original)
var decoded = gmssl.bytes_decode(encoded)
check_eq("U01: bytes_encode returns bytes", typeof(encoded), "bytes_array")
check_eq("U02: bytes_decode returns string", typeof(decoded), "string")
check_eq("U03: round-trip preserves data", decoded, original)

section("hex_encode / hex_decode")

var data = gmssl.bytes_encode("ABC")
var hex_str = gmssl.hex_encode(data)
check_eq("U04: hex_encode produces string", typeof(hex_str), "string")
check_eq("U05: hex_encode correct", hex_str, "414243")
var hex_decoded = gmssl.hex_decode(gmssl.bytes_encode(hex_str))
check_eq("U06: hex round-trip", gmssl.bytes_decode(hex_decoded), "ABC")

section("base64_encode / base64_decode")

var b64_str = gmssl.base64_encode(data)
check_eq("U07: base64_encode produces string", typeof(b64_str), "string")
var b64_decoded = gmssl.base64_decode(gmssl.bytes_encode(b64_str))
check_eq("U08: base64 round-trip", gmssl.bytes_decode(b64_decoded), "ABC")

section("rand_bytes")

var r1 = gmssl.rand_bytes(16)
var r2 = gmssl.rand_bytes(16)
check_eq("U09: rand_bytes correct length", r1.size, 16)
check("U10: rand_bytes non-deterministic", r1 != r2)

section("rand_chars")

var rc1 = gmssl.rand_chars(16, 1234)
var rc2 = gmssl.rand_chars(16, 1234)
check_eq("U11: rand_chars correct length", rc1.size, 16)
check_eq("U12: rand_chars deterministic with same seed", rc1, rc2)
var rc3 = gmssl.rand_chars(16, 5678)
check("U13: rand_chars different seed different output", rc1 != rc3)

section("empty input handling")

var empty_bytes = gmssl.bytes_encode("")
check_eq("U14: hex_encode empty", gmssl.hex_encode(empty_bytes), "")
check_eq("U15: base64_encode empty", gmssl.base64_encode(empty_bytes), "")

system.out.println("")
system.out.println("=== Results ===")
system.out.println("PASS: " + _pass)
system.out.println("FAIL: " + _fail)
if _fail > 0
    system.exit(1)
end

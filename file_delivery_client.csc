import network
import gmssl

var addr = context.cmd_args.at(1)
var trust_dgst = context.cmd_args.at(2)
var file_path = context.cmd_args.at(3)

using network
using system
using iostream

function send_request(sock, length)
    var head = to_string(length)
    while head.size < 32
        head += " "
    end
    sock.send(head)
    if sock.receive(32) == "READY"
        return true
    else
        return false
    end
end

function send_content(sock, buff)
    if send_request(sock, buff.size)
        sock.send(buff)
        if sock.receive(32) != "FINISH"
            out.println("Error")
        end
    end
end

function receive_content(sock)
    var size = sock.receive(32)
    size.cut(size.size - size.find(" ", 0))
    var length = size.to_number()
    sock.send("READY")
    var buff = sock.receive(length)
    sock.send("FINISH")
    return buff
end

function read_file(path)
    var fs = fstream(path, openmode.in)
    var buff = new string
    while !fs.eof()
        buff += fs.getline()+"\r\n"
    end
    return buff
end

system.out.println("Connect to " + addr + " port 1024")
var sock = new tcp.socket
sock.connect(tcp.endpoint(addr, 1024))

# authentication
var pubkey = gmssl.base64_decode(gmssl.bytes_encode(receive_content(sock)))
var pubkey_digest = gmssl.bytes_decode(gmssl.base64_encode(gmssl.sm3(pubkey)))
if trust_dgst.toupper() != "ALL" && trust_dgst != pubkey_digest
    send_content(sock, "AUTH_FAILED")
    system.out.println("Public Key Fingerprint Untrustworthy: " + pubkey_digest)
    system.out.println("Authentication failed.")
    system.exit(0)
end
send_content(sock, "AUTH_SUCCESS")
var session_id = gmssl.rand_bytes(32)
send_content(sock, gmssl.bytes_decode(gmssl.base64_encode(gmssl.sm2_encrypt(pubkey, session_id))))
var session_id_digest1 = receive_content(sock)
var session_id_digest2 = gmssl.bytes_decode(gmssl.base64_encode(gmssl.sm3(session_id)))
if session_id_digest1 != session_id_digest2
    system.out.println("Authentication failed.")
    system.exit(0)
end

# transmission
system.out.println("Authentication succeed. Starting transmission...")
var pass = gmssl.rand_bytes(gmssl.sm4_key_size)
send_content(sock, gmssl.bytes_decode(gmssl.base64_encode(gmssl.sm2_encrypt(pubkey, pass))))
var iv = gmssl.rand_bytes(gmssl.sm4_key_size)
send_content(sock, gmssl.bytes_decode(gmssl.base64_encode(iv)))
var file_content = read_file(file_path)
send_content(sock, gmssl.bytes_decode(gmssl.base64_encode(gmssl.sm4(gmssl.sm4_mode.ctr_encrypt, pass, iv, gmssl.bytes_encode(file_content)))))
system.out.println("Transmission finished.")

import network
import gmssl

var pubkey = gmssl.sm2_pem_read(context.cmd_args.at(1))
var privkey = gmssl.sm2_pem_read(context.cmd_args.at(2))
var keypass = context.cmd_args.at(3)

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

system.out.println("Listen on 127.0.0.1 port 1024")
var sock = new tcp.socket
var a = tcp.acceptor(tcp.endpoint("127.0.0.1", 1024))
runtime.wait_until(10000, []()->sock.accept(a), {})

# authentication
var session_id = gmssl.bytes_decode(gmssl.sm2_decrypt(privkey, keypass, gmssl.hex_decode(gmssl.bytes_encode(receive_content(sock)))))
var session_id_digest = gmssl.bytes_decode(gmssl.hex_encode(gmssl.sm3_digest(gmssl.bytes_encode(session_id))))
send_content(sock, session_id_digest)

# transmission
system.out.println("Authentication succeed. Starting transmission...")
var pass = receive_content(sock)
pass = gmssl.bytes_decode(gmssl.sm2_decrypt(privkey, keypass, gmssl.hex_decode(gmssl.bytes_encode(pass))))
var iv = receive_content(sock)
var file_content = receive_content(sock)
file_content = gmssl.bytes_decode(gmssl.sm4(gmssl.sm4_mode.ctr_decrypt, pass, iv, gmssl.hex_decode(gmssl.bytes_encode(file_content))))
gmssl.secure_clear(privkey)
system.out.println("Transmission finished.")
system.out.println("\n---- BEGINING OF CONTENT ----\n")
out.println(file_content)
system.out.println("\n---- END OF CONTENT ----\n")

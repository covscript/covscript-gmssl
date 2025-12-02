import network
import gmssl

var addr = context.cmd_args.at(1)
var pubkey = gmssl.sm2_pem_read(context.cmd_args.at(2), gmssl.pem_name_pbk)
var privkey = gmssl.sm2_pem_read(context.cmd_args.at(3), gmssl.pem_name_pvk)
var keypass = context.cmd_args.at(4)

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

system.out.println("Listen on " + addr + " port 1024")
var sock = new tcp.socket
var a = tcp.acceptor(tcp.endpoint(addr, 1024))

loop
    # establish connection
    system.out.println("Public Key Fingerprint: " + gmssl.bytes_decode(gmssl.base64_encode(gmssl.sm3(pubkey))))
    system.out.println("Waiting for incoming connection...")
    sock.accept(a)

    # authentication
    send_content(sock, gmssl.bytes_decode(gmssl.base64_encode(pubkey)))
    if receive_content(sock) != "AUTH_SUCCESS"
        system.out.println("Authentication failed.")
        sock.close()
        continue
    end
    var session_id = gmssl.sm2_decrypt(privkey, keypass, gmssl.base64_decode(gmssl.bytes_encode(receive_content(sock))))
    var session_id_digest = gmssl.bytes_decode(gmssl.base64_encode(gmssl.sm3(session_id)))
    send_content(sock, session_id_digest)
    system.out.println("Authentication succeed.")

    # transmission
    system.out.println("Starting transmission...")
    var pass = receive_content(sock)
    pass = gmssl.sm2_decrypt(privkey, keypass, gmssl.base64_decode(gmssl.bytes_encode(pass)))
    var iv = gmssl.base64_decode(gmssl.bytes_encode(receive_content(sock)))
    var file_content = receive_content(sock)
    file_content = gmssl.bytes_decode(gmssl.sm4(gmssl.sm4_mode.ctr_decrypt, pass, iv, gmssl.base64_decode(gmssl.bytes_encode(file_content))))
    system.out.println("Transmission finished.")
    sock.close()

    # print contents
    system.out.println("\n---- HEAD OF CONTENTS ----\n")
    out.println(file_content)
    system.out.println("\n---- TAIL OF CONTENTS ----\n")
end

import gmssl

var alice_passwd = null
system.console.echo(false)
loop
    system.out.print("Alice password: ")
    alice_passwd = system.in.getline()
    if alice_passwd.size < 6
        system.out.println("\nPassword must have 6 characters.")
        continue
    end
    system.out.print("\nRepeat password: ")
    if system.in.getline() != alice_passwd
        system.out.println("\nPassword not match.")
        continue
    else
        system.out.print("\n")
        break
    end
end
system.console.echo(true)

var (alice_pubkey, alice_privkey) = gmssl.sm2_key_generate(alice_passwd)
system.out.println("Alice Public Key: " + gmssl.hex_encode(alice_pubkey))

var bob_passwd = null
system.console.echo(false)
loop
    system.out.print("Bob password: ")
    bob_passwd = system.in.getline()
    if bob_passwd.size < 6
        system.out.println("\nPassword must have 6 characters.")
        continue
    end
    system.out.print("\nRepeat password: ")
    if system.in.getline() != bob_passwd
        system.out.println("\nPassword not match.")
        continue
    else
        system.out.print("\n")
        break
    end
end
system.console.echo(true)

var (bob_pubkey, bob_privkey) = gmssl.sm2_key_generate(bob_passwd)
system.out.println("Bob Public Key: " + gmssl.hex_encode(bob_pubkey))

system.out.println("\n--- ECDH Key Agreement ---")
var alice_shared = gmssl.sm2_ecdh(alice_privkey, alice_passwd, bob_pubkey)
var bob_shared = gmssl.sm2_ecdh(bob_privkey, bob_passwd, alice_pubkey)

system.out.println("Alice shared secret: " + gmssl.hex_encode(alice_shared))
system.out.println("Bob shared secret:   " + gmssl.hex_encode(bob_shared))
system.out.println("Shared secrets match: " + (alice_shared == bob_shared))

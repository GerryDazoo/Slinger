from ctypes import *

def encipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0)
    delta = 0x61C88647
    n = 32
    w = [0,0]

    while(n>0):
        sum.value -= delta
        y.value += ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        z.value += ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w

def decipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0xc6ef3720)
    delta = 0x9e3779b9
    n = 32
    w = [0,0]

    while(n>0):
        z.value -= ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        y.value -= ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        sum.value -= delta
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w
    
def Crypt( data, key ):
    bytes = b''
    info = [int.from_bytes(data[i:i+4],byteorder='little')  for i in range(0, len(data), 4)]
    for i in range(0, len(info), 2):
        chunk = [info[i], info[i+1]] 
        ciphertext = encipher(chunk, key)
        bytes = bytes + ciphertext[0].to_bytes(4, byteorder='little') + ciphertext[1].to_bytes(4, byteorder='little')
    return bytes
    
def Decrypt( data, key ):
    bytes = b''
    info = [int.from_bytes(data[i:i+4],byteorder='little')  for i in range(0, len(data), 4)]
    for i in range(0, len(info), 2):
        chunk = [info[i], info[i+1]] 
        cleartext = decipher(chunk, key)
        bytes = bytes + cleartext[0].to_bytes(4, byteorder='little') + cleartext[1].to_bytes(4, byteorder='little')
    return bytes


# <!!!!!!!!!!!!解密!解开我，你将获得全部信息!!!!!!!!!!!!!!!!!!>
# 6B562E2D3E7B6C61636078616C666C62

# #include <stdio.h>

# void reverseBits(unsigned char* password) {
#     int i, j;
#     unsigned char temp;

#     for (i = 0; i < 16; i++) {
#         temp = 0;
#         for (j = 0; j < 8; j++) {
#             temp |= ((password[i] >> j) & 1) << (7 - j);
#         }
#         password[i] = temp;
#     }
# }

# void swapPositions(unsigned char* password) {
#     int i;
#     unsigned char temp[16];
#     int positions[16] =
#             {
#                     13, 4, 0, 5,
#                     2, 12, 11, 8,
#                     10, 6, 1, 9,
#                     3, 15, 7, 14
#             };

#     for (i = 0; i < 16; i++) {
#         temp[positions[i]] = password[i];
#     }

#     for (i = 0; i < 16; i++) {
#         password[i] = temp[i];
#     }
# }

# void leftShiftBytes(unsigned char* password) {
#     for (int i = 0; i < 16; i++) {
#         password[i] = password[i] << 3 | password[i] >> 5;
#     }
# }



# void xorWithKeys(unsigned char* password, unsigned int round) {
#     int i;
#     for (i = 0; i < 16; i++) {
#         password[i] ^= (unsigned char)(0x78 * round & 0xFF);
#     }
# }

# void encryptPassword(unsigned char* password) {
#     int i;
#     unsigned int round;

#     for (round = 0; round < 16; round++) {
#         reverseBits(password);
#         swapPositions(password);
#         leftShiftBytes(password);
#         xorWithKeys(password, round);
#     }
# }

# int main() {
#     unsigned char password[17] = "1234567890";
#     printf("加密前的口令为：\n");
#     for (int i = 0; i < 16; i++) {
#         printf("%02X ", password[i]);
#     }
#     encryptPassword(password);
#     printf("加密后的口令为：\n");
#     for (int i = 0; i < 16; i++) {
#         printf("%02X ", password[i]);
#     }
#     printf("\n");
#     return 0;
# }

from Crypto.Util.number import *

password = b"1234567890" + b"\x00" * 7
c = long_to_bytes(0x6B562E2D3E7B6C61636078616C666C62).decode()

def xorwithkeys_inv(password,round):
    temp = ''
    for i in range(16):
        temp += chr(ord(password[i])^((0x78 * round) & 0xFF))
    return temp

def leftshiftbytes_inv(password):
    temp = ''
    for p in password:
        p = bin(ord(p))[2:].rjust(8,'0')
        temp += chr(int(p[5:] + p[:5], 2))
    return temp

def swappositions_inv(password):
    temp = ''
    positions = [13, 4, 0, 5, 2, 12, 11, 8, 10, 6, 1, 9, 3, 15, 7, 14]
    for i in range(16):
        temp += password[positions[i]]
    return temp

def swapPositions(password):
    temp = [0] * 16
    positions = [13, 4, 0, 5, 2, 12, 11, 8, 10, 6, 1, 9, 3, 15, 7, 14]
    for i in range(16):
        temp[positions[i]] = password[i]
    return temp

def reversebits_inv(password):
    temp = ''
    for p in password:
        p = bin(ord(p))[2:].rjust(8,'0')
        temp += chr(int(p[::-1], 2))

    return temp


for round in range(15, -1, -1):
    c = xorwithkeys_inv(c, round)
    c = leftshiftbytes_inv(c)
    c = swappositions_inv(c)
    c = reversebits_inv(c)

print(c)    # pdksidicndjh%^&6


'''
from Crypto.Util.number import *
a = long_to_bytes(0x6B562E2D3E7B6C61636078616C666C62).decode()
print(a)

for round in range(15,-1,-1):

 newa= ""
 for each in a:
  newa += chr(ord(each)^((0x78*round)&0xff))
 a = newa

 #print(a)
 newa = ""

 for each in a: 
  tmp = bin(ord(each))[2:].rjust(8,'0')
  atmp = tmp[5:]+tmp[:5]
  newa += chr(int(atmp,2))
 a = newa



 table = [13, 4, 0, 5,2, 12, 11, 8,10, 6, 1, 9,3, 15, 7, 14]

 newa = ""
 for i in range(16):
  newa += a[table[i]]
 a = newa

 
 newa  = ""
 for each in a:
  abin = bin(ord(each))[2:].rjust(8,'0')
  abinr = abin[::-1]
  newa += chr(int(abinr,2))
 a = newa
print(a)    # pdksidicndjh%^&6


'''
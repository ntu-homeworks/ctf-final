from pwn import *
from Crypto.Cipher import AES
import string

key='Ad5xBvZR1HVhE6**'
plain='Thi5 i$ 7he p!4int3x7 0f AES-CBC'
cplain='1f****************************8452fe2ad18a9e5e26887d133a13d7b818'
cflag='9c2ea756ed9ca3c05d541f7df961b3569e5f85a3387a818ed4c23db57aeeb1e4'


cflaghex=unhex(cflag)
cflaghex_b1=cflaghex[:16]
clfaghex_b2=cflaghex[16:32]


cplain_b2=cplain[-32:]
cplainhex_b2=unhex(cplain_b2)
plain_b2=plain[-16:]
plain_b1=plain[:16]

keyl=list(key)
keys=[]
guessb1=[]
"""
for i in xrange(256):
    for j in xrange(256):
       keyl[-1]=chr(i)
       keyl[-2]=chr(j)
       trykey=''.join(keyl)
       d=AES.new(trykey,AES.MODE_CBC,'\0'*16)
       test=d.decrypt('\0'*16+cplainhex_b2)
       test1=xor(test[-16:],plain_b2)
       
       if test1[0]=='\x1f' and test1[15]=='\x84':
           print hexdump(test1)
           print hexdump(trykey)
           keys.append(trykey)
           guessb1.append(test1)
           print enhex(test1)
"""
key1='Ad5xBvZR1HVhE6#3'
block='1f102dd31c83fd46f32138931b145384'
cplain_b1=unhex(block)

dd=AES.new(key1,AES.MODE_CBC,'\0'*16)
tmp=dd.decrypt(cplain_b1)
iv=xor(tmp,plain_b1)

dd2=AES.new(key1,AES.MODE_CBC,iv)
final = dd2.decrypt(cflaghex)
print hexdump(final)
print final

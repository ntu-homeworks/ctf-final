from pwn import *
import string
r=remote('csie.ctf.tw',10180)
r.recvuntil('G: ')
flag_enc=r.recvuntil('\n')
f=b64d(flag_enc)
c1=[]
c2=[]
ciphers=[]
r.recvline()
for i in range(25):
    ciphers.append(b64d(r.recvline(keepends=False)))#keepend=false
    #print list(ciphers[-1]),len(ciphers[-1])
    c1.append(ciphers[-1][0:16])
    #print list(c1[-1]),len(c1[-1])
    c2.append(ciphers[-1][16:32])
c1=map(list,zip(*c1)) #transpose the t
cc=map(list,zip(*ciphers))
flist=[]
for idx in xrange(len(cc)):
    tmp=[]
    for i in xrange(256):
        if all( c in string.digits+string.letters  for c in xor(i,''.join(cc[idx]))) :
            tmp.append( xor(f[idx],i))
    #print '======'
    flist.append(''.join(tmp))
import itertools
#final=reduce(lambda a,b:list(itertools.product(a, b)),flist)
final = list(itertools.product(*flist))
for i in final:
    a=''.join(i)
    if 'CTF{' in a and 'th3' in a and '$!mi14r_7o_th3_' in a :
        print a

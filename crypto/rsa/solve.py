#!/usr/bin/python

import pwnlib.tubes as pwntube
import pwnlib.util.fiddling as bitfn
from struct import *
import sys, time
from sympy.ntheory.modular import crt
from decimal import *
print 'RSA'
import sys
sys.setrecursionlimit(1500)
ns=[]
cs=[]
with open('output') as myfile :
    for i in xrange(17):
        n=myfile.readline()[3:-1]
        e=myfile.readline()[3:-1]
        c=myfile.readline()[3:-1]
        if e == '7':
            ns.append(n)
            cs.append(c)
        
                
ns=map(int,ns)
cs=map(int,cs)

from sympy import integer_nthroot

def isprintable(s, codec='utf8'):
	try: s.decode(codec)
	except UnicodeDecodeError: 
		return False
	else: 
		return True

def int_nthroot(n, r): # returns (rounded root, whether root is int) 
	(root, exact) = integer_nthroot(n,r)
	if exact:
		return root
	else:
		return None

def CRT(ds, rs):
    '''
    Chinese Remainder Theorem
    ds: array of dividers
    rs: array of remainders
    Return the number s such that s mod ds[i] = rs[i]
    '''
    length = len(ds)
    if not length == len(rs):
        print "The lengths of the two must be the same"
        return None

    p = i = prod = 1 
    s = 0
    for i in range(length): 
        prod *= ds[i]
    for i in range(length):
        p = prod // ds[i]
        s += rs[i] * modInv(p, ds[i]) * p
    return s % prod


def modInv(a, m):
    '''
    Return r such that a*r mod m = 1
    '''
    g, x, y = eGCD(a, m)
    if g != 1:
        print("no inverse")
        exit()
        return None
    else:
        return x % m
def eGCD(a, b):
    '''
    Extended Euclidean gcd. Return g,x,y such that ax+by=g=gcd(a,b)
    '''
    if a == 0: 
        return (b, 0, 1)
    else:
        g, y, x = eGCD(b%a, a)
        return (g, x-(b//a)*y, y)
def execute(keys, cs):
    '''
    ns: array of n
    e: public exponent
    cs: array of cipher text
    '''
    ns = []
    for key in keys:
        ns.append(key.n)
        e = keys[0].e
    return decrypt(ns,cs,e)

def decrypt(ns,cs,e):
    s =CRT(ns, cs)
    pt =int_nthroot(s, e)
    if pt is not None:
        return pt
    else:
        print "Cannot find %dth root of %s" % (e, hex(s))
        return None
        
aa=decrypt(ns,cs,7)
print format(aa,'x').decode('hex')
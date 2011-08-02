# This library is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see <http://www.gnu.org/licenses/> or <http://www.gnu.org/licenses/lgpl.txt>.

import urllib, urllib2
import httplib, socket
import struct
import base64
import string
import hashlib
import hmac
import random
import socket

# This file is part of 'NTLM Authorization Proxy Server' http://sourceforge.net/projects/ntlmaps/
# Copyright 2001 Dmitry A. Rozmanov <dima@xenon.spb.ru>
#
# This library is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see <http://www.gnu.org/licenses/> or <http://www.gnu.org/licenses/lgpl.txt>.

C = 0x1000000000L

def norm(n):
    return n & 0xFFFFFFFFL

class U32:
    v = 0L

    def __init__(self, value = 0):
        self.v = C + norm(abs(long(value)))

    def set(self, value = 0):
        self.v = C + norm(abs(long(value)))

    def __repr__(self):
        return hex(norm(self.v))

    def __long__(self): return long(norm(self.v))
    def __int__(self): return int(norm(self.v))
    def __chr__(self): return chr(norm(self.v))

    def __add__(self, b):
        r = U32()
        r.v = C + norm(self.v + b.v)
        return r

    def __sub__(self, b):
        r = U32()
        if self.v < b.v:
            r.v = C + norm(0x100000000L - (b.v - self.v))
        else: r.v = C + norm(self.v - b.v)
        return r

    def __mul__(self, b):
        r = U32()
        r.v = C + norm(self.v * b.v)
        return r

    def __div__(self, b):
        r = U32()
        r.v = C + (norm(self.v) / norm(b.v))
        return r

    def __mod__(self, b):
        r = U32()
        r.v = C + (norm(self.v) % norm(b.v))
        return r

    def __neg__(self): return U32(self.v)
    def __pos__(self): return U32(self.v)
    def __abs__(self): return U32(self.v)

    def __invert__(self):
        r = U32()
        r.v = C + norm(~self.v)
        return r

    def __lshift__(self, b):
        r = U32()
        r.v = C + norm(self.v << b)
        return r

    def __rshift__(self, b):
        r = U32()
        r.v = C + (norm(self.v) >> b)
        return r

    def __and__(self, b):
        r = U32()
        r.v = C + norm(self.v & b.v)
        return r

    def __or__(self, b):
        r = U32()
        r.v = C + norm(self.v | b.v)
        return r

    def __xor__(self, b):
        r = U32()
        r.v = C + norm(self.v ^ b.v)
        return r

    def __not__(self):
        return U32(not norm(self.v))

    def truth(self):
        return norm(self.v)

    def __cmp__(self, b):
        if norm(self.v) > norm(b.v): return 1
        elif norm(self.v) < norm(b.v): return -1
        else: return 0

    def __nonzero__(self):
        return norm(self.v)

# --NON ASCII COMMENT ELIDED--
#typedef unsigned char des_cblock[8];
#define HDRSIZE 4

def c2l(c):
    "char[4] to unsigned long"
    l = U32(c[0])
    l = l | (U32(c[1]) << 8)
    l = l | (U32(c[2]) << 16)
    l = l | (U32(c[3]) << 24)
    return l

def c2ln(c,l1,l2,n):
    "char[n] to two unsigned long???"
    c = c + n
    l1, l2 = U32(0), U32(0)

    f = 0
    if n == 8:
        l2 = l2 | (U32(c[7]) << 24)
        f = 1
    if f or (n == 7):
        l2 = l2 | (U32(c[6]) << 16)
        f = 1
    if f or (n == 6):
        l2 = l2 | (U32(c[5]) << 8)
        f = 1
    if f or (n == 5):
        l2 = l2 | U32(c[4])
        f = 1
    if f or (n == 4):
        l1 = l1 | (U32(c[3]) << 24)
        f = 1
    if f or (n == 3):
        l1 = l1 | (U32(c[2]) << 16)
        f = 1
    if f or (n == 2):
        l1 = l1 | (U32(c[1]) << 8)
        f = 1
    if f or (n == 1):
        l1 = l1 | U32(c[0])
    return (l1, l2)

def l2c(l):
    "unsigned long to char[4]"
    c = []
    c.append(int(l & U32(0xFF)))
    c.append(int((l >> 8) & U32(0xFF)))
    c.append(int((l >> 16) & U32(0xFF)))
    c.append(int((l >> 24) & U32(0xFF)))
    return c

def n2l(c, l):
    "network to host long"
    l = U32(c[0] << 24)
    l = l | (U32(c[1]) << 16)
    l = l | (U32(c[2]) << 8)
    l = l | (U32(c[3]))
    return l

def l2n(l, c):
    "host to network long"
    c = []
    c.append(int((l >> 24) & U32(0xFF)))
    c.append(int((l >> 16) & U32(0xFF)))
    c.append(int((l >>  8) & U32(0xFF)))
    c.append(int((l      ) & U32(0xFF)))
    return c

def l2cn(l1, l2, c, n):
    ""
    for i in range(n): c.append(0x00)
    f = 0
    if f or (n == 8):
        c[7] = int((l2 >> 24) & U32(0xFF))
        f = 1
    if f or (n == 7):
        c[6] = int((l2 >> 16) & U32(0xFF))
        f = 1
    if f or (n == 6):
        c[5] = int((l2 >>  8) & U32(0xFF))
        f = 1
    if f or (n == 5):
        c[4] = int((l2      ) & U32(0xFF))
        f = 1
    if f or (n == 4):
        c[3] = int((l1 >> 24) & U32(0xFF))
        f = 1
    if f or (n == 3):
        c[2] = int((l1 >> 16) & U32(0xFF))
        f = 1
    if f or (n == 2):
        c[1] = int((l1 >>  8) & U32(0xFF))
        f = 1
    if f or (n == 1):
        c[0] = int((l1      ) & U32(0xFF))
        f = 1
    return c[:n]

# array of data
# static unsigned long des_SPtrans[8][64]={
# static unsigned long des_skb[8][64]={
des_SPtrans =\
[
#nibble 0
[
U32(0x00820200L), U32(0x00020000L), U32(0x80800000L), U32(0x80820200L),
U32(0x00800000L), U32(0x80020200L), U32(0x80020000L), U32(0x80800000L),
U32(0x80020200L), U32(0x00820200L), U32(0x00820000L), U32(0x80000200L),
U32(0x80800200L), U32(0x00800000L), U32(0x00000000L), U32(0x80020000L),
U32(0x00020000L), U32(0x80000000L), U32(0x00800200L), U32(0x00020200L),
U32(0x80820200L), U32(0x00820000L), U32(0x80000200L), U32(0x00800200L),
U32(0x80000000L), U32(0x00000200L), U32(0x00020200L), U32(0x80820000L),
U32(0x00000200L), U32(0x80800200L), U32(0x80820000L), U32(0x00000000L),
U32(0x00000000L), U32(0x80820200L), U32(0x00800200L), U32(0x80020000L),
U32(0x00820200L), U32(0x00020000L), U32(0x80000200L), U32(0x00800200L),
U32(0x80820000L), U32(0x00000200L), U32(0x00020200L), U32(0x80800000L),
U32(0x80020200L), U32(0x80000000L), U32(0x80800000L), U32(0x00820000L),
U32(0x80820200L), U32(0x00020200L), U32(0x00820000L), U32(0x80800200L),
U32(0x00800000L), U32(0x80000200L), U32(0x80020000L), U32(0x00000000L),
U32(0x00020000L), U32(0x00800000L), U32(0x80800200L), U32(0x00820200L),
U32(0x80000000L), U32(0x80820000L), U32(0x00000200L), U32(0x80020200L),
],

#nibble 1
[
U32(0x10042004L), U32(0x00000000L), U32(0x00042000L), U32(0x10040000L),
U32(0x10000004L), U32(0x00002004L), U32(0x10002000L), U32(0x00042000L),
U32(0x00002000L), U32(0x10040004L), U32(0x00000004L), U32(0x10002000L),
U32(0x00040004L), U32(0x10042000L), U32(0x10040000L), U32(0x00000004L),
U32(0x00040000L), U32(0x10002004L), U32(0x10040004L), U32(0x00002000L),
U32(0x00042004L), U32(0x10000000L), U32(0x00000000L), U32(0x00040004L),
U32(0x10002004L), U32(0x00042004L), U32(0x10042000L), U32(0x10000004L),
U32(0x10000000L), U32(0x00040000L), U32(0x00002004L), U32(0x10042004L),
U32(0x00040004L), U32(0x10042000L), U32(0x10002000L), U32(0x00042004L),
U32(0x10042004L), U32(0x00040004L), U32(0x10000004L), U32(0x00000000L),
U32(0x10000000L), U32(0x00002004L), U32(0x00040000L), U32(0x10040004L),
U32(0x00002000L), U32(0x10000000L), U32(0x00042004L), U32(0x10002004L),
U32(0x10042000L), U32(0x00002000L), U32(0x00000000L), U32(0x10000004L),
U32(0x00000004L), U32(0x10042004L), U32(0x00042000L), U32(0x10040000L),
U32(0x10040004L), U32(0x00040000L), U32(0x00002004L), U32(0x10002000L),
U32(0x10002004L), U32(0x00000004L), U32(0x10040000L), U32(0x00042000L),
],

#nibble 2
[
U32(0x41000000L), U32(0x01010040L), U32(0x00000040L), U32(0x41000040L),
U32(0x40010000L), U32(0x01000000L), U32(0x41000040L), U32(0x00010040L),
U32(0x01000040L), U32(0x00010000L), U32(0x01010000L), U32(0x40000000L),
U32(0x41010040L), U32(0x40000040L), U32(0x40000000L), U32(0x41010000L),
U32(0x00000000L), U32(0x40010000L), U32(0x01010040L), U32(0x00000040L),
U32(0x40000040L), U32(0x41010040L), U32(0x00010000L), U32(0x41000000L),
U32(0x41010000L), U32(0x01000040L), U32(0x40010040L), U32(0x01010000L),
U32(0x00010040L), U32(0x00000000L), U32(0x01000000L), U32(0x40010040L),
U32(0x01010040L), U32(0x00000040L), U32(0x40000000L), U32(0x00010000L),
U32(0x40000040L), U32(0x40010000L), U32(0x01010000L), U32(0x41000040L),
U32(0x00000000L), U32(0x01010040L), U32(0x00010040L), U32(0x41010000L),
U32(0x40010000L), U32(0x01000000L), U32(0x41010040L), U32(0x40000000L),
U32(0x40010040L), U32(0x41000000L), U32(0x01000000L), U32(0x41010040L),
U32(0x00010000L), U32(0x01000040L), U32(0x41000040L), U32(0x00010040L),
U32(0x01000040L), U32(0x00000000L), U32(0x41010000L), U32(0x40000040L),
U32(0x41000000L), U32(0x40010040L), U32(0x00000040L), U32(0x01010000L),
],

#nibble 3
[
U32(0x00100402L), U32(0x04000400L), U32(0x00000002L), U32(0x04100402L),
U32(0x00000000L), U32(0x04100000L), U32(0x04000402L), U32(0x00100002L),
U32(0x04100400L), U32(0x04000002L), U32(0x04000000L), U32(0x00000402L),
U32(0x04000002L), U32(0x00100402L), U32(0x00100000L), U32(0x04000000L),
U32(0x04100002L), U32(0x00100400L), U32(0x00000400L), U32(0x00000002L),
U32(0x00100400L), U32(0x04000402L), U32(0x04100000L), U32(0x00000400L),
U32(0x00000402L), U32(0x00000000L), U32(0x00100002L), U32(0x04100400L),
U32(0x04000400L), U32(0x04100002L), U32(0x04100402L), U32(0x00100000L),
U32(0x04100002L), U32(0x00000402L), U32(0x00100000L), U32(0x04000002L),
U32(0x00100400L), U32(0x04000400L), U32(0x00000002L), U32(0x04100000L),
U32(0x04000402L), U32(0x00000000L), U32(0x00000400L), U32(0x00100002L),
U32(0x00000000L), U32(0x04100002L), U32(0x04100400L), U32(0x00000400L),
U32(0x04000000L), U32(0x04100402L), U32(0x00100402L), U32(0x00100000L),
U32(0x04100402L), U32(0x00000002L), U32(0x04000400L), U32(0x00100402L),
U32(0x00100002L), U32(0x00100400L), U32(0x04100000L), U32(0x04000402L),
U32(0x00000402L), U32(0x04000000L), U32(0x04000002L), U32(0x04100400L),
],

#nibble 4
[
U32(0x02000000L), U32(0x00004000L), U32(0x00000100L), U32(0x02004108L),
U32(0x02004008L), U32(0x02000100L), U32(0x00004108L), U32(0x02004000L),
U32(0x00004000L), U32(0x00000008L), U32(0x02000008L), U32(0x00004100L),
U32(0x02000108L), U32(0x02004008L), U32(0x02004100L), U32(0x00000000L),
U32(0x00004100L), U32(0x02000000L), U32(0x00004008L), U32(0x00000108L),
U32(0x02000100L), U32(0x00004108L), U32(0x00000000L), U32(0x02000008L),
U32(0x00000008L), U32(0x02000108L), U32(0x02004108L), U32(0x00004008L),
U32(0x02004000L), U32(0x00000100L), U32(0x00000108L), U32(0x02004100L),
U32(0x02004100L), U32(0x02000108L), U32(0x00004008L), U32(0x02004000L),
U32(0x00004000L), U32(0x00000008L), U32(0x02000008L), U32(0x02000100L),
U32(0x02000000L), U32(0x00004100L), U32(0x02004108L), U32(0x00000000L),
U32(0x00004108L), U32(0x02000000L), U32(0x00000100L), U32(0x00004008L),
U32(0x02000108L), U32(0x00000100L), U32(0x00000000L), U32(0x02004108L),
U32(0x02004008L), U32(0x02004100L), U32(0x00000108L), U32(0x00004000L),
U32(0x00004100L), U32(0x02004008L), U32(0x02000100L), U32(0x00000108L),
U32(0x00000008L), U32(0x00004108L), U32(0x02004000L), U32(0x02000008L),
],

#nibble 5
[
U32(0x20000010L), U32(0x00080010L), U32(0x00000000L), U32(0x20080800L),
U32(0x00080010L), U32(0x00000800L), U32(0x20000810L), U32(0x00080000L),
U32(0x00000810L), U32(0x20080810L), U32(0x00080800L), U32(0x20000000L),
U32(0x20000800L), U32(0x20000010L), U32(0x20080000L), U32(0x00080810L),
U32(0x00080000L), U32(0x20000810L), U32(0x20080010L), U32(0x00000000L),
U32(0x00000800L), U32(0x00000010L), U32(0x20080800L), U32(0x20080010L),
U32(0x20080810L), U32(0x20080000L), U32(0x20000000L), U32(0x00000810L),
U32(0x00000010L), U32(0x00080800L), U32(0x00080810L), U32(0x20000800L),
U32(0x00000810L), U32(0x20000000L), U32(0x20000800L), U32(0x00080810L),
U32(0x20080800L), U32(0x00080010L), U32(0x00000000L), U32(0x20000800L),
U32(0x20000000L), U32(0x00000800L), U32(0x20080010L), U32(0x00080000L),
U32(0x00080010L), U32(0x20080810L), U32(0x00080800L), U32(0x00000010L),
U32(0x20080810L), U32(0x00080800L), U32(0x00080000L), U32(0x20000810L),
U32(0x20000010L), U32(0x20080000L), U32(0x00080810L), U32(0x00000000L),
U32(0x00000800L), U32(0x20000010L), U32(0x20000810L), U32(0x20080800L),
U32(0x20080000L), U32(0x00000810L), U32(0x00000010L), U32(0x20080010L),
],

#nibble 6
[
U32(0x00001000L), U32(0x00000080L), U32(0x00400080L), U32(0x00400001L),
U32(0x00401081L), U32(0x00001001L), U32(0x00001080L), U32(0x00000000L),
U32(0x00400000L), U32(0x00400081L), U32(0x00000081L), U32(0x00401000L),
U32(0x00000001L), U32(0x00401080L), U32(0x00401000L), U32(0x00000081L),
U32(0x00400081L), U32(0x00001000L), U32(0x00001001L), U32(0x00401081L),
U32(0x00000000L), U32(0x00400080L), U32(0x00400001L), U32(0x00001080L),
U32(0x00401001L), U32(0x00001081L), U32(0x00401080L), U32(0x00000001L),
U32(0x00001081L), U32(0x00401001L), U32(0x00000080L), U32(0x00400000L),
U32(0x00001081L), U32(0x00401000L), U32(0x00401001L), U32(0x00000081L),
U32(0x00001000L), U32(0x00000080L), U32(0x00400000L), U32(0x00401001L),
U32(0x00400081L), U32(0x00001081L), U32(0x00001080L), U32(0x00000000L),
U32(0x00000080L), U32(0x00400001L), U32(0x00000001L), U32(0x00400080L),
U32(0x00000000L), U32(0x00400081L), U32(0x00400080L), U32(0x00001080L),
U32(0x00000081L), U32(0x00001000L), U32(0x00401081L), U32(0x00400000L),
U32(0x00401080L), U32(0x00000001L), U32(0x00001001L), U32(0x00401081L),
U32(0x00400001L), U32(0x00401080L), U32(0x00401000L), U32(0x00001001L),
],

#nibble 7
[
U32(0x08200020L), U32(0x08208000L), U32(0x00008020L), U32(0x00000000L),
U32(0x08008000L), U32(0x00200020L), U32(0x08200000L), U32(0x08208020L),
U32(0x00000020L), U32(0x08000000L), U32(0x00208000L), U32(0x00008020L),
U32(0x00208020L), U32(0x08008020L), U32(0x08000020L), U32(0x08200000L),
U32(0x00008000L), U32(0x00208020L), U32(0x00200020L), U32(0x08008000L),
U32(0x08208020L), U32(0x08000020L), U32(0x00000000L), U32(0x00208000L),
U32(0x08000000L), U32(0x00200000L), U32(0x08008020L), U32(0x08200020L),
U32(0x00200000L), U32(0x00008000L), U32(0x08208000L), U32(0x00000020L),
U32(0x00200000L), U32(0x00008000L), U32(0x08000020L), U32(0x08208020L),
U32(0x00008020L), U32(0x08000000L), U32(0x00000000L), U32(0x00208000L),
U32(0x08200020L), U32(0x08008020L), U32(0x08008000L), U32(0x00200020L),
U32(0x08208000L), U32(0x00000020L), U32(0x00200020L), U32(0x08008000L),
U32(0x08208020L), U32(0x00200000L), U32(0x08200000L), U32(0x08000020L),
U32(0x00208000L), U32(0x00008020L), U32(0x08008020L), U32(0x08200000L),
U32(0x00000020L), U32(0x08208000L), U32(0x00208020L), U32(0x00000000L),
U32(0x08000000L), U32(0x08200020L), U32(0x00008000L), U32(0x00208020L),
],
]

#static unsigned long des_skb[8][64]={

des_skb = \
[
#for C bits (numbered as per FIPS 46) 1 2 3 4 5 6
[
U32(0x00000000L),U32(0x00000010L),U32(0x20000000L),U32(0x20000010L),
U32(0x00010000L),U32(0x00010010L),U32(0x20010000L),U32(0x20010010L),
U32(0x00000800L),U32(0x00000810L),U32(0x20000800L),U32(0x20000810L),
U32(0x00010800L),U32(0x00010810L),U32(0x20010800L),U32(0x20010810L),
U32(0x00000020L),U32(0x00000030L),U32(0x20000020L),U32(0x20000030L),
U32(0x00010020L),U32(0x00010030L),U32(0x20010020L),U32(0x20010030L),
U32(0x00000820L),U32(0x00000830L),U32(0x20000820L),U32(0x20000830L),
U32(0x00010820L),U32(0x00010830L),U32(0x20010820L),U32(0x20010830L),
U32(0x00080000L),U32(0x00080010L),U32(0x20080000L),U32(0x20080010L),
U32(0x00090000L),U32(0x00090010L),U32(0x20090000L),U32(0x20090010L),
U32(0x00080800L),U32(0x00080810L),U32(0x20080800L),U32(0x20080810L),
U32(0x00090800L),U32(0x00090810L),U32(0x20090800L),U32(0x20090810L),
U32(0x00080020L),U32(0x00080030L),U32(0x20080020L),U32(0x20080030L),
U32(0x00090020L),U32(0x00090030L),U32(0x20090020L),U32(0x20090030L),
U32(0x00080820L),U32(0x00080830L),U32(0x20080820L),U32(0x20080830L),
U32(0x00090820L),U32(0x00090830L),U32(0x20090820L),U32(0x20090830L),
],

#for C bits (numbered as per FIPS 46) 7 8 10 11 12 13
[
U32(0x00000000L),U32(0x02000000L),U32(0x00002000L),U32(0x02002000L),
U32(0x00200000L),U32(0x02200000L),U32(0x00202000L),U32(0x02202000L),
U32(0x00000004L),U32(0x02000004L),U32(0x00002004L),U32(0x02002004L),
U32(0x00200004L),U32(0x02200004L),U32(0x00202004L),U32(0x02202004L),
U32(0x00000400L),U32(0x02000400L),U32(0x00002400L),U32(0x02002400L),
U32(0x00200400L),U32(0x02200400L),U32(0x00202400L),U32(0x02202400L),
U32(0x00000404L),U32(0x02000404L),U32(0x00002404L),U32(0x02002404L),
U32(0x00200404L),U32(0x02200404L),U32(0x00202404L),U32(0x02202404L),
U32(0x10000000L),U32(0x12000000L),U32(0x10002000L),U32(0x12002000L),
U32(0x10200000L),U32(0x12200000L),U32(0x10202000L),U32(0x12202000L),
U32(0x10000004L),U32(0x12000004L),U32(0x10002004L),U32(0x12002004L),
U32(0x10200004L),U32(0x12200004L),U32(0x10202004L),U32(0x12202004L),
U32(0x10000400L),U32(0x12000400L),U32(0x10002400L),U32(0x12002400L),
U32(0x10200400L),U32(0x12200400L),U32(0x10202400L),U32(0x12202400L),
U32(0x10000404L),U32(0x12000404L),U32(0x10002404L),U32(0x12002404L),
U32(0x10200404L),U32(0x12200404L),U32(0x10202404L),U32(0x12202404L),
],

#for C bits (numbered as per FIPS 46) 14 15 16 17 19 20
[
U32(0x00000000L),U32(0x00000001L),U32(0x00040000L),U32(0x00040001L),
U32(0x01000000L),U32(0x01000001L),U32(0x01040000L),U32(0x01040001L),
U32(0x00000002L),U32(0x00000003L),U32(0x00040002L),U32(0x00040003L),
U32(0x01000002L),U32(0x01000003L),U32(0x01040002L),U32(0x01040003L),
U32(0x00000200L),U32(0x00000201L),U32(0x00040200L),U32(0x00040201L),
U32(0x01000200L),U32(0x01000201L),U32(0x01040200L),U32(0x01040201L),
U32(0x00000202L),U32(0x00000203L),U32(0x00040202L),U32(0x00040203L),
U32(0x01000202L),U32(0x01000203L),U32(0x01040202L),U32(0x01040203L),
U32(0x08000000L),U32(0x08000001L),U32(0x08040000L),U32(0x08040001L),
U32(0x09000000L),U32(0x09000001L),U32(0x09040000L),U32(0x09040001L),
U32(0x08000002L),U32(0x08000003L),U32(0x08040002L),U32(0x08040003L),
U32(0x09000002L),U32(0x09000003L),U32(0x09040002L),U32(0x09040003L),
U32(0x08000200L),U32(0x08000201L),U32(0x08040200L),U32(0x08040201L),
U32(0x09000200L),U32(0x09000201L),U32(0x09040200L),U32(0x09040201L),
U32(0x08000202L),U32(0x08000203L),U32(0x08040202L),U32(0x08040203L),
U32(0x09000202L),U32(0x09000203L),U32(0x09040202L),U32(0x09040203L),
],

#for C bits (numbered as per FIPS 46) 21 23 24 26 27 28
[
U32(0x00000000L),U32(0x00100000L),U32(0x00000100L),U32(0x00100100L),
U32(0x00000008L),U32(0x00100008L),U32(0x00000108L),U32(0x00100108L),
U32(0x00001000L),U32(0x00101000L),U32(0x00001100L),U32(0x00101100L),
U32(0x00001008L),U32(0x00101008L),U32(0x00001108L),U32(0x00101108L),
U32(0x04000000L),U32(0x04100000L),U32(0x04000100L),U32(0x04100100L),
U32(0x04000008L),U32(0x04100008L),U32(0x04000108L),U32(0x04100108L),
U32(0x04001000L),U32(0x04101000L),U32(0x04001100L),U32(0x04101100L),
U32(0x04001008L),U32(0x04101008L),U32(0x04001108L),U32(0x04101108L),
U32(0x00020000L),U32(0x00120000L),U32(0x00020100L),U32(0x00120100L),
U32(0x00020008L),U32(0x00120008L),U32(0x00020108L),U32(0x00120108L),
U32(0x00021000L),U32(0x00121000L),U32(0x00021100L),U32(0x00121100L),
U32(0x00021008L),U32(0x00121008L),U32(0x00021108L),U32(0x00121108L),
U32(0x04020000L),U32(0x04120000L),U32(0x04020100L),U32(0x04120100L),
U32(0x04020008L),U32(0x04120008L),U32(0x04020108L),U32(0x04120108L),
U32(0x04021000L),U32(0x04121000L),U32(0x04021100L),U32(0x04121100L),
U32(0x04021008L),U32(0x04121008L),U32(0x04021108L),U32(0x04121108L),
],

#for D bits (numbered as per FIPS 46) 1 2 3 4 5 6
[
U32(0x00000000L),U32(0x10000000L),U32(0x00010000L),U32(0x10010000L),
U32(0x00000004L),U32(0x10000004L),U32(0x00010004L),U32(0x10010004L),
U32(0x20000000L),U32(0x30000000L),U32(0x20010000L),U32(0x30010000L),
U32(0x20000004L),U32(0x30000004L),U32(0x20010004L),U32(0x30010004L),
U32(0x00100000L),U32(0x10100000L),U32(0x00110000L),U32(0x10110000L),
U32(0x00100004L),U32(0x10100004L),U32(0x00110004L),U32(0x10110004L),
U32(0x20100000L),U32(0x30100000L),U32(0x20110000L),U32(0x30110000L),
U32(0x20100004L),U32(0x30100004L),U32(0x20110004L),U32(0x30110004L),
U32(0x00001000L),U32(0x10001000L),U32(0x00011000L),U32(0x10011000L),
U32(0x00001004L),U32(0x10001004L),U32(0x00011004L),U32(0x10011004L),
U32(0x20001000L),U32(0x30001000L),U32(0x20011000L),U32(0x30011000L),
U32(0x20001004L),U32(0x30001004L),U32(0x20011004L),U32(0x30011004L),
U32(0x00101000L),U32(0x10101000L),U32(0x00111000L),U32(0x10111000L),
U32(0x00101004L),U32(0x10101004L),U32(0x00111004L),U32(0x10111004L),
U32(0x20101000L),U32(0x30101000L),U32(0x20111000L),U32(0x30111000L),
U32(0x20101004L),U32(0x30101004L),U32(0x20111004L),U32(0x30111004L),
],

#for D bits (numbered as per FIPS 46) 8 9 11 12 13 14
[
U32(0x00000000L),U32(0x08000000L),U32(0x00000008L),U32(0x08000008L),
U32(0x00000400L),U32(0x08000400L),U32(0x00000408L),U32(0x08000408L),
U32(0x00020000L),U32(0x08020000L),U32(0x00020008L),U32(0x08020008L),
U32(0x00020400L),U32(0x08020400L),U32(0x00020408L),U32(0x08020408L),
U32(0x00000001L),U32(0x08000001L),U32(0x00000009L),U32(0x08000009L),
U32(0x00000401L),U32(0x08000401L),U32(0x00000409L),U32(0x08000409L),
U32(0x00020001L),U32(0x08020001L),U32(0x00020009L),U32(0x08020009L),
U32(0x00020401L),U32(0x08020401L),U32(0x00020409L),U32(0x08020409L),
U32(0x02000000L),U32(0x0A000000L),U32(0x02000008L),U32(0x0A000008L),
U32(0x02000400L),U32(0x0A000400L),U32(0x02000408L),U32(0x0A000408L),
U32(0x02020000L),U32(0x0A020000L),U32(0x02020008L),U32(0x0A020008L),
U32(0x02020400L),U32(0x0A020400L),U32(0x02020408L),U32(0x0A020408L),
U32(0x02000001L),U32(0x0A000001L),U32(0x02000009L),U32(0x0A000009L),
U32(0x02000401L),U32(0x0A000401L),U32(0x02000409L),U32(0x0A000409L),
U32(0x02020001L),U32(0x0A020001L),U32(0x02020009L),U32(0x0A020009L),
U32(0x02020401L),U32(0x0A020401L),U32(0x02020409L),U32(0x0A020409L),
],

#for D bits (numbered as per FIPS 46) 16 17 18 19 20 21
[
U32(0x00000000L),U32(0x00000100L),U32(0x00080000L),U32(0x00080100L),
U32(0x01000000L),U32(0x01000100L),U32(0x01080000L),U32(0x01080100L),
U32(0x00000010L),U32(0x00000110L),U32(0x00080010L),U32(0x00080110L),
U32(0x01000010L),U32(0x01000110L),U32(0x01080010L),U32(0x01080110L),
U32(0x00200000L),U32(0x00200100L),U32(0x00280000L),U32(0x00280100L),
U32(0x01200000L),U32(0x01200100L),U32(0x01280000L),U32(0x01280100L),
U32(0x00200010L),U32(0x00200110L),U32(0x00280010L),U32(0x00280110L),
U32(0x01200010L),U32(0x01200110L),U32(0x01280010L),U32(0x01280110L),
U32(0x00000200L),U32(0x00000300L),U32(0x00080200L),U32(0x00080300L),
U32(0x01000200L),U32(0x01000300L),U32(0x01080200L),U32(0x01080300L),
U32(0x00000210L),U32(0x00000310L),U32(0x00080210L),U32(0x00080310L),
U32(0x01000210L),U32(0x01000310L),U32(0x01080210L),U32(0x01080310L),
U32(0x00200200L),U32(0x00200300L),U32(0x00280200L),U32(0x00280300L),
U32(0x01200200L),U32(0x01200300L),U32(0x01280200L),U32(0x01280300L),
U32(0x00200210L),U32(0x00200310L),U32(0x00280210L),U32(0x00280310L),
U32(0x01200210L),U32(0x01200310L),U32(0x01280210L),U32(0x01280310L),
],

#for D bits (numbered as per FIPS 46) 22 23 24 25 27 28
[
U32(0x00000000L),U32(0x04000000L),U32(0x00040000L),U32(0x04040000L),
U32(0x00000002L),U32(0x04000002L),U32(0x00040002L),U32(0x04040002L),
U32(0x00002000L),U32(0x04002000L),U32(0x00042000L),U32(0x04042000L),
U32(0x00002002L),U32(0x04002002L),U32(0x00042002L),U32(0x04042002L),
U32(0x00000020L),U32(0x04000020L),U32(0x00040020L),U32(0x04040020L),
U32(0x00000022L),U32(0x04000022L),U32(0x00040022L),U32(0x04040022L),
U32(0x00002020L),U32(0x04002020L),U32(0x00042020L),U32(0x04042020L),
U32(0x00002022L),U32(0x04002022L),U32(0x00042022L),U32(0x04042022L),
U32(0x00000800L),U32(0x04000800L),U32(0x00040800L),U32(0x04040800L),
U32(0x00000802L),U32(0x04000802L),U32(0x00040802L),U32(0x04040802L),
U32(0x00002800L),U32(0x04002800L),U32(0x00042800L),U32(0x04042800L),
U32(0x00002802L),U32(0x04002802L),U32(0x00042802L),U32(0x04042802L),
U32(0x00000820L),U32(0x04000820L),U32(0x00040820L),U32(0x04040820L),
U32(0x00000822L),U32(0x04000822L),U32(0x00040822L),U32(0x04040822L),
U32(0x00002820L),U32(0x04002820L),U32(0x00042820L),U32(0x04042820L),
U32(0x00002822L),U32(0x04002822L),U32(0x00042822L),U32(0x04042822L),
]

]

def D_ENCRYPT(tup, u, t, s):
    L, R, S = tup
    #print 'LRS1', L, R, S, u, t, '-->',
    u = (R ^ s[S])
    t = R ^ s[S + 1]
    t = ((t >> 4) + (t << 28))
    L = L ^ (des_SPtrans[1][int((t    ) & U32(0x3f))] | \
        des_SPtrans[3][int((t >>  8) & U32(0x3f))] | \
        des_SPtrans[5][int((t >> 16) & U32(0x3f))] | \
        des_SPtrans[7][int((t >> 24) & U32(0x3f))] | \
        des_SPtrans[0][int((u      ) & U32(0x3f))] | \
        des_SPtrans[2][int((u >>  8) & U32(0x3f))] | \
        des_SPtrans[4][int((u >> 16) & U32(0x3f))] | \
        des_SPtrans[6][int((u >> 24) & U32(0x3f))])
    #print 'LRS:', L, R, S, u, t
    return ((L, R, S), u, t, s)


def PERM_OP (tup, n, m):
    "tup - (a, b, t)"
    a, b, t = tup
    t = ((a >> n) ^ b) & m
    b = b ^ t
    a = a ^ (t << n)
    return (a, b, t)

def HPERM_OP (tup, n, m):
    "tup - (a, t)"
    a, t = tup
    t = ((a << (16 - n)) ^ a) & m
    a = a ^ t ^ (t >> (16 - n))
    return (a, t)

shifts2 = [0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0]

class DES:
    KeySched = None # des_key_schedule

    def __init__(self, key_str):
        # key - UChar[8]
        key = []
        for i in key_str: key.append(ord(i))
        #print 'key:', key
        self.KeySched = des_set_key(key)
        #print 'schedule:', self.KeySched, len(self.KeySched)

    def decrypt(self, str):
        # block - UChar[]
        block = []
        for i in str: block.append(ord(i))
        #print block
        block = des_ecb_encrypt(block, self.KeySched, 0)
        res = ''
        for i in block: res = res + (chr(i))
        return res

    def encrypt(self, str):
        # block - UChar[]
        block = []
        for i in str: block.append(ord(i))
        block = des_ecb_encrypt(block, self.KeySched, 1)
        res = ''
        for i in block: res = res + (chr(i))
        return res






#------------------------
def des_encript(input, ks, encrypt):
    # input - U32[]
    # output - U32[]
    # ks - des_key_shedule - U32[2][16]
    # encrypt - int
    # l, r, t, u - U32
    # i - int
    # s - U32[]

    l = input[0]
    r = input[1]
    t = U32(0)
    u = U32(0)

    r, l, t = PERM_OP((r, l, t),  4, U32(0x0f0f0f0fL))
    l, r, t = PERM_OP((l, r, t), 16, U32(0x0000ffffL))
    r, l, t = PERM_OP((r, l, t),  2, U32(0x33333333L))
    l, r, t = PERM_OP((l, r, t),  8, U32(0x00ff00ffL))
    r, l, t = PERM_OP((r, l, t),  1, U32(0x55555555L))

    t = (r << 1)|(r >> 31)
    r = (l << 1)|(l >> 31)
    l = t

    s = ks # ???????????????
    #print l, r
    if(encrypt):
        for i in range(0, 32, 4):
            rtup, u, t, s = D_ENCRYPT((l, r, i + 0), u, t, s)
            l = rtup[0]
            r = rtup[1]
            rtup, u, t, s = D_ENCRYPT((r, l, i + 2), u, t, s)
            r = rtup[0]
            l = rtup[1]
    else:
        for i in range(30, 0, -4):
            rtup, u, t, s = D_ENCRYPT((l, r, i - 0), u, t, s)
            l = rtup[0]
            r = rtup[1]
            rtup, u, t, s = D_ENCRYPT((r, l, i - 2), u, t, s)
            r = rtup[0]
            l = rtup[1]
    #print l, r
    l = (l >> 1)|(l << 31)
    r = (r >> 1)|(r << 31)

    r, l, t = PERM_OP((r, l, t),  1, U32(0x55555555L))
    l, r, t = PERM_OP((l, r, t),  8, U32(0x00ff00ffL))
    r, l, t = PERM_OP((r, l, t),  2, U32(0x33333333L))
    l, r, t = PERM_OP((l, r, t), 16, U32(0x0000ffffL))
    r, l, t = PERM_OP((r, l, t),  4, U32(0x0f0f0f0fL))

    output = [l]
    output.append(r)
    l, r, t, u = U32(0), U32(0), U32(0), U32(0)
    return output

def des_ecb_encrypt(input, ks, encrypt):
    # input - des_cblock - UChar[8]
    # output - des_cblock - UChar[8]
    # ks - des_key_shedule - U32[2][16]
    # encrypt - int

    #print input
    l0 = c2l(input[0:4])
    l1 = c2l(input[4:8])
    ll = [l0]
    ll.append(l1)
    #print ll
    ll = des_encript(ll, ks, encrypt)
    #print ll
    l0 = ll[0]
    l1 = ll[1]
    output = l2c(l0)
    output = output + l2c(l1)
    #print output
    l0, l1, ll[0], ll[1] = U32(0), U32(0), U32(0), U32(0)
    return output

def des_set_key(key):
    # key - des_cblock - UChar[8]
    # schedule - des_key_schedule

    # register unsigned long c,d,t,s;
    # register unsigned char *in;
    # register unsigned long *k;
    # register int i;

    #k = schedule
    # in = key

    k = []
    c = c2l(key[0:4])
    d = c2l(key[4:8])
    t = U32(0)

    d, c, t = PERM_OP((d, c, t), 4, U32(0x0f0f0f0fL))
    c, t = HPERM_OP((c, t), -2, U32(0xcccc0000L))
    d, t = HPERM_OP((d, t), -2, U32(0xcccc0000L))
    d, c, t = PERM_OP((d, c, t), 1, U32(0x55555555L))
    c, d, t = PERM_OP((c, d, t), 8, U32(0x00ff00ffL))
    d, c, t = PERM_OP((d, c, t), 1, U32(0x55555555L))

    d = (((d & U32(0x000000ffL)) << 16)|(d & U32(0x0000ff00L))|((d & U32(0x00ff0000L)) >> 16)|((c & U32(0xf0000000L)) >> 4))
    c  = c & U32(0x0fffffffL)

    for i in range(16):
        if (shifts2[i]):
            c = ((c >> 2)|(c << 26))
            d = ((d >> 2)|(d << 26))
        else:
            c = ((c >> 1)|(c << 27))
            d = ((d >> 1)|(d << 27))
        c = c & U32(0x0fffffffL)
        d = d & U32(0x0fffffffL)

        s=  des_skb[0][int((c    ) & U32(0x3f))]|\
            des_skb[1][int(((c>> 6) & U32(0x03))|((c>> 7) & U32(0x3c)))]|\
            des_skb[2][int(((c>>13) & U32(0x0f))|((c>>14) & U32(0x30)))]|\
            des_skb[3][int(((c>>20) & U32(0x01))|((c>>21) & U32(0x06)) | ((c>>22) & U32(0x38)))]

        t=  des_skb[4][int((d    ) & U32(0x3f)                )]|\
            des_skb[5][int(((d>> 7) & U32(0x03))|((d>> 8) & U32(0x3c)))]|\
            des_skb[6][int((d>>15) & U32(0x3f)                )]|\
            des_skb[7][int(((d>>21) & U32(0x0f))|((d>>22) & U32(0x30)))]
        #print s, t

        k.append(((t << 16)|(s & U32(0x0000ffffL))) & U32(0xffffffffL))
        s = ((s >> 16)|(t & U32(0xffff0000L)))
        s = (s << 4)|(s >> 28)
        k.append(s & U32(0xffffffffL))

    schedule = k

    return schedule


#---------------------------------------------------------------------
class DES:

    des_c_obj = None

    #-----------------------------------------------------------------
    def __init__(self, key_str):
        ""
        k = str_to_key56(key_str)
        k = key56_to_key64(k)
        key_str = ''
        for i in k:
            key_str += chr(i & 0xFF)
        self.des_c_obj = DES(key_str)

    #-----------------------------------------------------------------
    def encrypt(self, plain_text):
        ""
        return self.des_c_obj.encrypt(plain_text)

    #-----------------------------------------------------------------
    def decrypt(self, crypted_text):
        ""
        return self.des_c_obj.decrypt(crypted_text)

#---------------------------------------------------------------------
#Some Helpers
#---------------------------------------------------------------------

DESException = 'DESException'

#---------------------------------------------------------------------
def str_to_key56(key_str):
    ""
    if type(key_str) != type(''):
        #rise DESException, 'ERROR. Wrong key type.'
        pass
    if len(key_str) < 7:
        key_str = key_str + '\000\000\000\000\000\000\000'[:(7 - len(key_str))]
    key_56 = []
    for i in key_str[:7]: key_56.append(ord(i))

    return key_56

#---------------------------------------------------------------------
def key56_to_key64(key_56):
    ""
    key = []
    for i in range(8): key.append(0)

    key[0] = key_56[0];
    key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1);
    key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2);
    key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3);
    key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4);
    key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5);
    key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6);
    key[7] =  (key_56[6] << 1) & 0xFF;

    key = set_key_odd_parity(key)

    return key

#---------------------------------------------------------------------
def set_key_odd_parity(key):
    ""
    for i in range(len(key)):
        for k in range(7):
            bit = 0
            t = key[i] >> k
            bit = (t ^ bit) & 0x1
        key[i] = (key[i] & 0xFE) | bit

    return key

NTLM_NegotiateUnicode                =  0x00000001
NTLM_NegotiateOEM                    =  0x00000002
NTLM_RequestTarget                   =  0x00000004
NTLM_Unknown9                        =  0x00000008
NTLM_NegotiateSign                   =  0x00000010
NTLM_NegotiateSeal                   =  0x00000020
NTLM_NegotiateDatagram               =  0x00000040
NTLM_NegotiateLanManagerKey          =  0x00000080
NTLM_Unknown8                        =  0x00000100
NTLM_NegotiateNTLM                   =  0x00000200
NTLM_NegotiateNTOnly                 =  0x00000400
NTLM_Anonymous                       =  0x00000800
NTLM_NegotiateOemDomainSupplied      =  0x00001000
NTLM_NegotiateOemWorkstationSupplied =  0x00002000
NTLM_Unknown6                        =  0x00004000
NTLM_NegotiateAlwaysSign             =  0x00008000
NTLM_TargetTypeDomain                =  0x00010000
NTLM_TargetTypeServer                =  0x00020000
NTLM_TargetTypeShare                 =  0x00040000
NTLM_NegotiateExtendedSecurity       =  0x00080000
NTLM_NegotiateIdentify               =  0x00100000
NTLM_Unknown5                        =  0x00200000
NTLM_RequestNonNTSessionKey          =  0x00400000
NTLM_NegotiateTargetInfo             =  0x00800000
NTLM_Unknown4                        =  0x01000000
NTLM_NegotiateVersion                =  0x02000000
NTLM_Unknown3                        =  0x04000000
NTLM_Unknown2                        =  0x08000000
NTLM_Unknown1                        =  0x10000000
NTLM_Negotiate128                    =  0x20000000
NTLM_NegotiateKeyExchange            =  0x40000000
NTLM_Negotiate56                     =  0x80000000

# we send these flags with our type 1 message
NTLM_TYPE1_FLAGS = (NTLM_NegotiateUnicode | \
                    NTLM_NegotiateOEM | \
                    NTLM_RequestTarget | \
                    NTLM_NegotiateNTLM | \
                    NTLM_NegotiateOemDomainSupplied | \
                    NTLM_NegotiateOemWorkstationSupplied | \
                    NTLM_NegotiateAlwaysSign | \
                    NTLM_NegotiateExtendedSecurity | \
                    NTLM_NegotiateVersion | \
                    NTLM_Negotiate128 | \
                    NTLM_Negotiate56 )
NTLM_TYPE2_FLAGS = (NTLM_NegotiateUnicode | \
                    NTLM_RequestTarget | \
                    NTLM_NegotiateNTLM | \
                    NTLM_NegotiateAlwaysSign | \
                    NTLM_NegotiateExtendedSecurity | \
                    NTLM_NegotiateTargetInfo | \
                    NTLM_NegotiateVersion | \
                    NTLM_Negotiate128 | \
                    NTLM_Negotiate56)

NTLM_MsvAvEOL             = 0 # Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
NTLM_MsvAvNbComputerName  = 1 # The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
NTLM_MsvAvNbDomainName    = 2 # The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
NTLM_MsvAvDnsComputerName = 3 # The server's Active Directory DNS computer name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvDnsDomainName   = 4 # The server's Active Directory DNS domain name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvDnsTreeName     = 5 # The server's Active Directory (AD) DNS forest tree name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvFlags           = 6 # A field containing a 32-bit value indicating server or client configuration. 0x00000001: indicates to the client that the account authentication is constrained. 0x00000002: indicates that the client is providing message integrity in the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.
NTLM_MsvAvTimestamp       = 7 # A FILETIME structure ([MS-DTYP] section 2.3.1) in little-endian byte order that contains the server local time.<12>
NTLM_MsAvRestrictions     = 8 #A Restriction_Encoding structure (section 2.2.2.2). The Value field contains a structure representing the integrity level of the security principal, as well as a MachineID created at computer startup to identify the calling machine. <13>


"""
utility functions for Microsoft NTLM authentication

References:
[MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol Specification
http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NLMP%5D.pdf

[MS-NTHT]: NTLM Over HTTP Protocol Specification
http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NTHT%5D.pdf

Cntlm Authentication Proxy
http://cntlm.awk.cz/

NTLM Authorization Proxy Server
http://sourceforge.net/projects/ntlmaps/

Optimized Attack for NTLM2 Session Response
http://www.blackhat.com/presentations/bh-asia-04/bh-jp-04-pdfs/bh-jp-04-seki.pdf
"""
def dump_NegotiateFlags(NegotiateFlags):
    if NegotiateFlags & NTLM_NegotiateUnicode:
        print "NTLM_NegotiateUnicode set"
    if NegotiateFlags & NTLM_NegotiateOEM:
        print "NTLM_NegotiateOEM set"
    if NegotiateFlags & NTLM_RequestTarget:
        print "NTLM_RequestTarget set"
    if NegotiateFlags & NTLM_Unknown9:
        print "NTLM_Unknown9 set"
    if NegotiateFlags & NTLM_NegotiateSign:
        print "NTLM_NegotiateSign set"
    if NegotiateFlags & NTLM_NegotiateSeal:
        print "NTLM_NegotiateSeal set"
    if NegotiateFlags & NTLM_NegotiateDatagram:
        print "NTLM_NegotiateDatagram set"
    if NegotiateFlags & NTLM_NegotiateLanManagerKey:
        print "NTLM_NegotiateLanManagerKey set"
    if NegotiateFlags & NTLM_Unknown8:
        print "NTLM_Unknown8 set"
    if NegotiateFlags & NTLM_NegotiateNTLM:
        print "NTLM_NegotiateNTLM set"
    if NegotiateFlags & NTLM_NegotiateNTOnly:
        print "NTLM_NegotiateNTOnly set"
    if NegotiateFlags & NTLM_Anonymous:
        print "NTLM_Anonymous set"
    if NegotiateFlags & NTLM_NegotiateOemDomainSupplied:
        print "NTLM_NegotiateOemDomainSupplied set"
    if NegotiateFlags & NTLM_NegotiateOemWorkstationSupplied:
        print "NTLM_NegotiateOemWorkstationSupplied set"
    if NegotiateFlags & NTLM_Unknown6:
        print "NTLM_Unknown6 set"
    if NegotiateFlags & NTLM_NegotiateAlwaysSign:
        print "NTLM_NegotiateAlwaysSign set"
    if NegotiateFlags & NTLM_TargetTypeDomain:
        print "NTLM_TargetTypeDomain set"
    if NegotiateFlags & NTLM_TargetTypeServer:
        print "NTLM_TargetTypeServer set"
    if NegotiateFlags & NTLM_TargetTypeShare:
        print "NTLM_TargetTypeShare set"
    if NegotiateFlags & NTLM_NegotiateExtendedSecurity:
        print "NTLM_NegotiateExtendedSecurity set"
    if NegotiateFlags & NTLM_NegotiateIdentify:
        print "NTLM_NegotiateIdentify set"
    if NegotiateFlags & NTLM_Unknown5:
        print "NTLM_Unknown5 set"
    if NegotiateFlags & NTLM_RequestNonNTSessionKey:
        print "NTLM_RequestNonNTSessionKey set"
    if NegotiateFlags & NTLM_NegotiateTargetInfo:
        print "NTLM_NegotiateTargetInfo set"
    if NegotiateFlags & NTLM_Unknown4:
        print "NTLM_Unknown4 set"
    if NegotiateFlags & NTLM_NegotiateVersion:
        print "NTLM_NegotiateVersion set"
    if NegotiateFlags & NTLM_Unknown3:
        print "NTLM_Unknown3 set"
    if NegotiateFlags & NTLM_Unknown2:
        print "NTLM_Unknown2 set"
    if NegotiateFlags & NTLM_Unknown1:
        print "NTLM_Unknown1 set"
    if NegotiateFlags & NTLM_Negotiate128:
        print "NTLM_Negotiate128 set"
    if NegotiateFlags & NTLM_NegotiateKeyExchange:
        print "NTLM_NegotiateKeyExchange set"
    if NegotiateFlags & NTLM_Negotiate56:
        print "NTLM_Negotiate56 set"

def create_NTLM_NEGOTIATE_MESSAGE(user):
    BODY_LENGTH = 40
    Payload_start = BODY_LENGTH # in bytes
    protocol = 'NTLMSSP\0'    #name

    type = struct.pack('<I',1) #type 1

    flags =  struct.pack('<I', NTLM_TYPE1_FLAGS)
    Workstation = socket.gethostname().upper().encode('ascii')
    user_parts = user.split('\\', 1)
    DomainName = user_parts[0].upper().encode('ascii')
    EncryptedRandomSessionKey = ""


    WorkstationLen = struct.pack('<H', len(Workstation))
    WorkstationMaxLen = struct.pack('<H', len(Workstation))
    WorkstationBufferOffset = struct.pack('<I', Payload_start)
    Payload_start += len(Workstation)
    DomainNameLen = struct.pack('<H', len(DomainName))
    DomainNameMaxLen = struct.pack('<H', len(DomainName))
    DomainNameBufferOffset = struct.pack('<I',Payload_start)
    Payload_start += len(DomainName)
    ProductMajorVersion = struct.pack('<B', 5)
    ProductMinorVersion = struct.pack('<B', 1)
    ProductBuild = struct.pack('<H', 2600)
    VersionReserved1 = struct.pack('<B', 0)
    VersionReserved2 = struct.pack('<B', 0)
    VersionReserved3 = struct.pack('<B', 0)
    NTLMRevisionCurrent = struct.pack('<B', 15)

    msg1 = protocol + type + flags + \
            DomainNameLen + DomainNameMaxLen + DomainNameBufferOffset + \
            WorkstationLen + WorkstationMaxLen + WorkstationBufferOffset + \
            ProductMajorVersion + ProductMinorVersion + ProductBuild + \
            VersionReserved1 + VersionReserved2 + VersionReserved3 + NTLMRevisionCurrent
    assert BODY_LENGTH==len(msg1), "BODY_LENGTH: %d != msg1: %d" % (BODY_LENGTH,len(msg1))
    msg1 += Workstation + DomainName
    msg1 = base64.encodestring(msg1)
    msg1 = string.replace(msg1, '\n', '')
    return msg1

def parse_NTLM_CHALLENGE_MESSAGE(msg2):
    ""
    msg2 = base64.decodestring(msg2)
    Signature = msg2[0:8]
    msg_type = struct.unpack("<I",msg2[8:12])[0]
    assert(msg_type==2)
    TargetNameLen = struct.unpack("<H",msg2[12:14])[0]
    TargetNameMaxLen = struct.unpack("<H",msg2[14:16])[0]
    TargetNameOffset = struct.unpack("<I",msg2[16:20])[0]
    TargetName = msg2[TargetNameOffset:TargetNameOffset+TargetNameMaxLen]
    NegotiateFlags = struct.unpack("<I",msg2[20:24])[0]
    ServerChallenge = msg2[24:32]
    Reserved = msg2[32:40]
    TargetInfoLen = struct.unpack("<H",msg2[40:42])[0]
    TargetInfoMaxLen = struct.unpack("<H",msg2[42:44])[0]
    TargetInfoOffset = struct.unpack("<I",msg2[44:48])[0]
    TargetInfo = msg2[TargetInfoOffset:TargetInfoOffset+TargetInfoLen]
    i=0
    TimeStamp = '\0'*8
    while(i<TargetInfoLen):
        AvId = struct.unpack("<H",TargetInfo[i:i+2])[0]
        AvLen = struct.unpack("<H",TargetInfo[i+2:i+4])[0]
        AvValue = TargetInfo[i+4:i+4+AvLen]
        i = i+4+AvLen
        if AvId == NTLM_MsvAvTimestamp:
            TimeStamp = AvValue
        #~ print AvId, AvValue.decode('utf-16')
    return (ServerChallenge, NegotiateFlags)

def create_NTLM_AUTHENTICATE_MESSAGE(nonce, user, domain, password, NegotiateFlags):
    ""
    is_unicode  = NegotiateFlags & NTLM_NegotiateUnicode
    is_NegotiateExtendedSecurity = NegotiateFlags & NTLM_NegotiateExtendedSecurity

    flags =  struct.pack('<I',NTLM_TYPE2_FLAGS)

    BODY_LENGTH = 72
    Payload_start = BODY_LENGTH # in bytes

    Workstation = socket.gethostname().upper()
    DomainName = domain.upper()
    UserName = user
    EncryptedRandomSessionKey = ""
    if is_unicode:
        Workstation = Workstation.encode('utf-16-le')
        DomainName = DomainName.encode('utf-16-le')
        UserName = UserName.encode('utf-16-le')
        EncryptedRandomSessionKey = EncryptedRandomSessionKey.encode('utf-16-le')
    LmChallengeResponse = calc_resp(create_LM_hashed_password_v1(password), nonce)
    NtChallengeResponse = calc_resp(create_NT_hashed_password_v1(password), nonce)

    if is_NegotiateExtendedSecurity:
        pwhash = create_NT_hashed_password_v1(password, UserName, DomainName)
        ClientChallenge = ""
        for i in range(8):
           ClientChallenge+= chr(random.getrandbits(8))
        (NtChallengeResponse, LmChallengeResponse) = ntlm2sr_calc_resp(pwhash, nonce, ClientChallenge) #='\x39 e3 f4 cd 59 c5 d8 60')
    Signature = 'NTLMSSP\0'
    MessageType = struct.pack('<I',3)  #type 3

    DomainNameLen = struct.pack('<H', len(DomainName))
    DomainNameMaxLen = struct.pack('<H', len(DomainName))
    DomainNameOffset = struct.pack('<I', Payload_start)
    Payload_start += len(DomainName)

    UserNameLen = struct.pack('<H', len(UserName))
    UserNameMaxLen = struct.pack('<H', len(UserName))
    UserNameOffset = struct.pack('<I', Payload_start)
    Payload_start += len(UserName)

    WorkstationLen = struct.pack('<H', len(Workstation))
    WorkstationMaxLen = struct.pack('<H', len(Workstation))
    WorkstationOffset = struct.pack('<I', Payload_start)
    Payload_start += len(Workstation)


    LmChallengeResponseLen = struct.pack('<H', len(LmChallengeResponse))
    LmChallengeResponseMaxLen = struct.pack('<H', len(LmChallengeResponse))
    LmChallengeResponseOffset = struct.pack('<I', Payload_start)
    Payload_start += len(LmChallengeResponse)

    NtChallengeResponseLen = struct.pack('<H', len(NtChallengeResponse))
    NtChallengeResponseMaxLen = struct.pack('<H', len(NtChallengeResponse))
    NtChallengeResponseOffset = struct.pack('<I', Payload_start)
    Payload_start += len(NtChallengeResponse)

    EncryptedRandomSessionKeyLen = struct.pack('<H', len(EncryptedRandomSessionKey))
    EncryptedRandomSessionKeyMaxLen = struct.pack('<H', len(EncryptedRandomSessionKey))
    EncryptedRandomSessionKeyOffset = struct.pack('<I',Payload_start)
    Payload_start +=  len(EncryptedRandomSessionKey)
    NegotiateFlags = flags

    ProductMajorVersion = struct.pack('<B', 5)
    ProductMinorVersion = struct.pack('<B', 1)
    ProductBuild = struct.pack('<H', 2600)
    VersionReserved1 = struct.pack('<B', 0)
    VersionReserved2 = struct.pack('<B', 0)
    VersionReserved3 = struct.pack('<B', 0)
    NTLMRevisionCurrent = struct.pack('<B', 15)

    MIC = struct.pack('<IIII',0,0,0,0)
    msg3 = Signature + MessageType + \
            LmChallengeResponseLen + LmChallengeResponseMaxLen + LmChallengeResponseOffset + \
            NtChallengeResponseLen + NtChallengeResponseMaxLen + NtChallengeResponseOffset + \
            DomainNameLen + DomainNameMaxLen + DomainNameOffset + \
            UserNameLen + UserNameMaxLen + UserNameOffset + \
            WorkstationLen + WorkstationMaxLen + WorkstationOffset + \
            EncryptedRandomSessionKeyLen + EncryptedRandomSessionKeyMaxLen + EncryptedRandomSessionKeyOffset + \
            NegotiateFlags + \
            ProductMajorVersion + ProductMinorVersion + ProductBuild + \
            VersionReserved1 + VersionReserved2 + VersionReserved3 + NTLMRevisionCurrent
    assert BODY_LENGTH==len(msg3), "BODY_LENGTH: %d != msg3: %d" % (BODY_LENGTH,len(msg3))
    Payload = DomainName + UserName + Workstation + LmChallengeResponse + NtChallengeResponse + EncryptedRandomSessionKey
    msg3 += Payload
    msg3 = base64.encodestring(msg3)
    msg3 = string.replace(msg3, '\n', '')
    return msg3

def calc_resp(password_hash, server_challenge):
    """calc_resp generates the LM response given a 16-byte password hash and the
        challenge from the Type-2 message.
        @param password_hash
            16-byte password hash
        @param server_challenge
            8-byte challenge from Type-2 message
        returns
            24-byte buffer to contain the LM response upon return
    """
    # padding with zeros to make the hash 21 bytes long
    password_hash = password_hash + '\0' * (21 - len(password_hash))
    res = ''
    dobj = DES(password_hash[0:7])
    res = res + dobj.encrypt(server_challenge[0:8])

    dobj = DES(password_hash[7:14])
    res = res + dobj.encrypt(server_challenge[0:8])

    dobj = DES(password_hash[14:21])
    res = res + dobj.encrypt(server_challenge[0:8])
    return res

def ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ServerName, ClientChallenge='\xaa'*8, Time='\0'*8):
    LmChallengeResponse = hmac.new(ResponseKeyLM, ServerChallenge+ClientChallenge).digest() + ClientChallenge

    Responserversion = '\x01'
    HiResponserversion = '\x01'
    temp = Responserversion + HiResponserversion + '\0'*6 + Time + ClientChallenge + '\0'*4 + ServerChallenge + '\0'*4
    NTProofStr  = hmac.new(ResponseKeyNT, ServerChallenge + temp).digest()
    NtChallengeResponse = NTProofStr + temp

    SessionBaseKey = hmac.new(ResponseKeyNT, NTProofStr).digest()
    return (NtChallengeResponse, LmChallengeResponse)

def ntlm2sr_calc_resp(ResponseKeyNT, ServerChallenge, ClientChallenge='\xaa'*8):
    import hashlib
    LmChallengeResponse = ClientChallenge + '\0'*16
    sess = hashlib.md5(ServerChallenge+ClientChallenge).digest()
    NtChallengeResponse = calc_resp(ResponseKeyNT, sess[0:8])
    return (NtChallengeResponse, LmChallengeResponse)

def create_LM_hashed_password_v1(passwd):
    "setup LanManager password"
    "create LanManager hashed password"

    # fix the password length to 14 bytes
    passwd = string.upper(passwd)
    lm_pw = passwd + '\0' * (14 - len(passwd))
    lm_pw = passwd[0:14]

    # do hash
    magic_str = "KGS!@#$%" # page 57 in [MS-NLMP]

    res = ''
    dobj = DES(lm_pw[0:7])
    res = res + dobj.encrypt(magic_str)

    dobj = DES(lm_pw[7:14])
    res = res + dobj.encrypt(magic_str)

    return res

def create_NT_hashed_password_v1(passwd, user=None, domain=None):
    "create NT hashed password"
    digest = hashlib.new('md4', passwd.encode('utf-16le')).digest()
    return digest

def create_NT_hashed_password_v2(passwd, user, domain):
    "create NT hashed password"
    digest = create_NT_hashed_password_v1(passwd)

    return hmac.new(digest, (user.upper()+domain).encode('utf-16le')).digest()
    return digest

def create_sessionbasekey(password):
    return hashlib.new('md4', create_NT_hashed_password_v1(password)).digest()

if __name__ == "__main__":
    def ByteToHex( byteStr ):
        """
        Convert a byte string to it's hex string representation e.g. for output.
        """
        return ' '.join( [ "%02X" % ord( x ) for x in byteStr ] )

    def HexToByte( hexStr ):
        """
        Convert a string hex byte values into a byte string. The Hex Byte values may
        or may not be space separated.
        """
        bytes = []

        hexStr = ''.join( hexStr.split(" ") )

        for i in range(0, len(hexStr), 2):
            bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

        return ''.join( bytes )

    ServerChallenge = HexToByte("01 23 45 67 89 ab cd ef")
    ClientChallenge = '\xaa'*8
    Time = '\x00'*8
    Workstation = "COMPUTER".encode('utf-16-le')
    ServerName = "Server".encode('utf-16-le')
    User = "User"
    Domain = "Domain"
    Password = "Password"
    RandomSessionKey = '\55'*16
    assert HexToByte("e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d") == create_LM_hashed_password_v1(Password)                  # [MS-NLMP] page 72
    assert HexToByte("a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52") == create_NT_hashed_password_v1(Password)    # [MS-NLMP] page 73
    assert HexToByte("d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84") == create_sessionbasekey(Password)
    assert HexToByte("67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94") == calc_resp(create_NT_hashed_password_v1(Password), ServerChallenge)
    assert HexToByte("98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13") == calc_resp(create_LM_hashed_password_v1(Password), ServerChallenge)

    (NTLMv1Response,LMv1Response) = ntlm2sr_calc_resp(create_NT_hashed_password_v1(Password), ServerChallenge, ClientChallenge)
    assert HexToByte("aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00") == LMv1Response  # [MS-NLMP] page 75
    assert HexToByte("75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8 1e 97 ed 26 83 26 72 32") == NTLMv1Response

    assert HexToByte("0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f") == create_NT_hashed_password_v2(Password, User, Domain)    # [MS-NLMP] page 76
    ResponseKeyLM = ResponseKeyNT = create_NT_hashed_password_v2(Password, User, Domain)
    (NTLMv2Response,LMv2Response) = ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ServerName, ClientChallenge, Time)
    assert HexToByte("86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa") == LMv2Response  # [MS-NLMP] page 76

    # expected failure
    # According to the spec in section '3.3.2 NTLM v2 Authentication' the NTLMv2Response should be longer than the value given on page 77 (this suggests a mistake in the spec)
    #~ assert HexToByte("68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c") == NTLMv2Response, "\nExpected: 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c\nActual:   %s" % ByteToHex(NTLMv2Response) # [MS-NLMP] page 77


class AbstractNtlmAuthHandler:
    def __init__(self, password_mgr=None, debuglevel=0):
        if password_mgr is None:
            password_mgr = HTTPPasswordMgr()
        self.passwd = password_mgr
        self.add_password = self.passwd.add_password
        self._debuglevel = debuglevel

    def set_http_debuglevel(self, level):
        self._debuglevel = level

    def http_error_authentication_required(self, auth_header_field, req, fp, headers):
        auth_header_value = headers.get(auth_header_field, None)
        if auth_header_field:
            if auth_header_value is not None and 'ntlm' in auth_header_value.lower():
                fp.close()
                return self.retry_using_http_NTLM_auth(req, auth_header_field, None, headers)

    def retry_using_http_NTLM_auth(self, req, auth_header_field, realm, headers):
        user, pw = self.passwd.find_user_password(realm, req.get_full_url())
        if pw is not None:
            # ntlm secures a socket, so we must use the same socket for the complete handshake
            headers = dict(req.headers)
            headers.update(req.unredirected_hdrs)
            auth = 'NTLM %s' % ntlm.create_NTLM_NEGOTIATE_MESSAGE(user)
            if req.headers.get(self.auth_header, None) == auth:
                return None
            headers[self.auth_header] = auth

            host = req.get_host()
            if not host:
                raise urllib2.URLError('no host given')
            h = None
            if req.get_full_url().startswith('https://'):
                h = httplib.HTTPSConnection(host) # will parse host:port
            else:
                h = httplib.HTTPConnection(host) # will parse host:port
            h.set_debuglevel(self._debuglevel)
            # we must keep the connection because NTLM authenticates the connection, not single requests
            headers["Connection"] = "Keep-Alive"
            headers = dict((name.title(), val) for name, val in headers.items())
            h.request(req.get_method(), req.get_selector(), req.data, headers)
            r = h.getresponse()
            r.begin()
            r._safe_read(int(r.getheader('content-length')))
            if r.getheader('set-cookie'):
                # this is important for some web applications that store authentication-related info in cookies (it took a long time to figure out)
                headers['Cookie'] = r.getheader('set-cookie')
            r.fp = None # remove the reference to the socket, so that it can not be closed by the response object (we want to keep the socket open)
            auth_header_value = r.getheader(auth_header_field, None)
            (ServerChallenge, NegotiateFlags) = ntlm.parse_NTLM_CHALLENGE_MESSAGE(auth_header_value[5:])
            user_parts = user.split('\\', 1)
            DomainName = user_parts[0].upper()
            UserName = user_parts[1]
            auth = 'NTLM %s' % ntlm.create_NTLM_AUTHENTICATE_MESSAGE(ServerChallenge, UserName, DomainName, pw, NegotiateFlags)
            headers[self.auth_header] = auth
            headers["Connection"] = "Close"
            headers = dict((name.title(), val) for name, val in headers.items())
            try:
                h.request(req.get_method(), req.get_selector(), req.data, headers)
                # none of the configured handlers are triggered, for example redirect-responses are not handled!
                response = h.getresponse()
                def notimplemented():
                    raise NotImplementedError
                response.readline = notimplemented
                infourl = urllib.addinfourl(response, response.msg, req.get_full_url())
                infourl.code = response.status
                infourl.msg = response.reason
                return infourl
            except socket.error, err:
                raise urllib2.URLError(err)
        else:
            return None


class HTTPNtlmAuthHandler(AbstractNtlmAuthHandler, urllib2.BaseHandler):

    auth_header = 'Authorization'

    def http_error_401(self, req, fp, code, msg, headers):
        return self.http_error_authentication_required('www-authenticate', req, fp, headers)


class ProxyNtlmAuthHandler(AbstractNtlmAuthHandler, urllib2.BaseHandler):
    """
        CAUTION: this class has NOT been tested at all!!!
        use at your own risk
    """
    auth_header = 'Proxy-authorization'

    def http_error_407(self, req, fp, code, msg, headers):
        return self.http_error_authentication_required('proxy-authenticate', req, fp, headers)


if __name__ == "__main__":
    url = "http://ntlmprotectedserver/securedfile.html"
    user = u'DOMAIN\\User'
    password = 'Password'

    passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, url, user , password)
    auth_basic = urllib2.HTTPBasicAuthHandler(passman)
    auth_digest = urllib2.HTTPDigestAuthHandler(passman)
    auth_NTLM = HTTPNtlmAuthHandler(passman)

    # disable proxies (just for testing)
    proxy_handler = urllib2.ProxyHandler({})

    opener = urllib2.build_opener(proxy_handler, auth_NTLM) #, auth_digest, auth_basic)

    urllib2.install_opener(opener)

    response = urllib2.urlopen(url)
    print(response.read())


#!/usr/bin/env python3

import io
import re
import sys
import argparse
from sympy import Matrix
from itertools import chain

# Convert string to integers. converts to uppercase,
# and includes spaces(any whitespace), periods and
# question marks to get to 29 chars (which is prime)
ALPHSIZE = 29
def toI(s):
    filt_s = re.sub("[^A-Z\s?.]","",s.upper())
    filt_s = re.sub("\.",chr(ord("A")-1),filt_s)
    #sheer luck that ? maps to ?
    #filt_s = re.sub("\?",chr(ord("A")-2),filt_s)
    filt_s = re.sub("\s+",chr(ord("A")-3),filt_s)
    return (map(lambda x:ord(x)-ord("A")+3,filt_s))

def toS(i):
    filt_s = "".join(list(map(lambda x:chr(x+ord("A")-3),i)))
    filt_s = re.sub(chr(ord("A")-1),".",filt_s)
    #filt_s = re.sub(chr(ord("A")-2),"?",filt_s)
    filt_s = re.sub(chr(ord("A")-3)," ",filt_s)
    return filt_s

# key string, matrix size
def toA(k,n):
    # needed length
    n2=n*n
    #shorten if too long
    buf = (list(k))[:n2]
    #lengthen if too short. fill with sequence, not zeros.
    #not great, but it's deterministic
    ary = buf+list(range(n2-len(buf)))
    # make sure it's invertible,
    # add the identity matrix until it is.
    m = Matrix(n,n,ary)
    while True:
        try:
            m.inv_mod(ALPHSIZE)
        except ValueError:
            m=(m+Matrix.eye(n))%ALPHSIZE
        else:
            return m


class Hill:
    #create encoding and decoding matrices
    def __init__(self,size, keystring):
        self.size = int(size)
        self.a_encode = toA(toI(keystring),size)
        self.a_decode = self.a_encode.inv_mod(ALPHSIZE)

    # pull the string from the input,
    # convert to a matrix of appropriate length
    # multiply with modulus
    # flatten back out and convert to string
    def process(self,input,m):
        buf = input.read()
        buf=list(toI(buf))
        # pad with spaces to make divisible by size.
        buf = buf + [0] * ((self.size-len(buf))%self.size)
        d = Matrix(self.size,int(len(buf)/self.size),buf)
        e = ((m*d)%ALPHSIZE).tolist()
        return (toS(chain.from_iterable(e)))

    # process using appropriate matrix
    def encode(self, input):
        return self.process(input,self.a_encode)

    def decode(self, input):
        return self.process(input,self.a_decode)


#######################################################
# Main program
# parse options

parser = argparse.ArgumentParser()
parser.add_argument("-decode",action='store_true',help="Decode instead of encode using the given key.")
parser.add_argument("-size",nargs='?',type=int,default=3,help="Size of the encryption array. Default: %(default)s")
parser.add_argument("key",help="key used to generate the encryption array.")
parser.add_argument("input_file", nargs='?',type=argparse.FileType('r'),default=sys.stdin,help="Default: stdin")
parser.add_argument("output_file", nargs='?',type=argparse.FileType('w'),default=sys.stdout,help="Default: stdout")
args = parser.parse_args()

# create encoder from key
crypt = Hill(args.size,args.key)
# encode or decode depending on flag.
if args.decode:
    args.output_file.write(crypt.decode(args.input_file)+'\n')
else:
    args.output_file.write(crypt.encode(args.input_file))

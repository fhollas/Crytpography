#!/usr/bin/python
# -*- coding: utf-8 -*-

import base64
import binascii, random
import time
from math import gcd


def judge_qr(y,p,q):
    if y**((q-1)/2) % q == 1 and y**((p-1)/2) % p == 1:
        #print(y,"quadratic residue =&gt; 0")
        return 1
    else:
        #print(y,"quadratic non-residue =&gt; 1")
        return 0

def choose_qnr(N,p,q):
    start_time=time.time()
    for y in range(N):
        if y**((q-1)/2) % q == (q-1) and y**((p-1)/2) % p == (p-1):
            #print "non-quadratic residue which is jacobi simbol +1",
            print(y)
    print("\nTime to generate Jacobi Symbols:", time.time()-start_time, "seconds")

def encryption(bin_str,N,p,q,z,ciphertxt):
    print("\n==Encryption")
    #print z
    start_time=time.time()
    for m in bin_str[2:]:
        #print m,
        while 1:
            x = random.randint(1,N)
            if gcd(x,N) :
                y = (x**2) % N
                #print x, "=&gt;", x**2, "=&gt;", y, " ",
            if judge_qr(y,p,q):
                y = ((int(z)**int(m))*(x**2))%N
                ciphertxt.append(y)
                break
            else:
                continue
        #print "\t-Encrypted string of ",bin_str[2:],"is",
        #for tmp in ciphertxt:
        #   print tmp,
    #print "\t-Encrypted string of ",bin_str[2:],"is",
    print(ciphertxt)
    print("\nEncryption time:", time.time()-start_time, "seconds")
        #print int_str_to_chr_str(ciphertxt),

def decryption(ciphertxt,p,q):
    print("\n\n==Decryption")
    start_time=time.time()
    decrypttxt = []
    decrypttxt.append('0')
    for x in ciphertxt:
        if judge_qr(x,p,q):
            decrypttxt.append('0')
            #print "0",
        else:
            decrypttxt.append('1')
            #print "1",
    decrypttxt =''.join(decrypttxt)
    print("\nDecryption time:", time.time()-start_time, "seconds")
    print("\n\n\tDecrypted string : ", decrypttxt)
    print("\n\n\tDecrypted integer : ", int(decrypttxt, 2))
    #print("\nDecrypted string : ",''.join(chr(int(decrypttxt[i:i+8],2)) for i in range(0,len(decrypttxt),8)))
    return decrypttxt

def add(enc1, enc2, N):
    ab = [enc1[i] * enc2[i] for i in range(len(enc1))]
    print("\n\n", ab)
    sum = [ab[i] % N for  i in range(len(ab))]
    print("\n\n\t Multiplied ciphertext:", sum)
    return sum

def bin2str(bin_str):

#    n = int(bin_str, 2)
#    unhex_str = binascii.unhexlify(‘%x’%n)
#    print unhex_str

    '''
    N = 11413
    p = 101
    q = 113
    ciphertxt = []
    '''
    N = 667
    p = 23
    q = 29
    ciphertxt = []
    
#z = 134

    print("Goldwasser-Micali probabilistic encryption")
    print("== Key generation")
    print("\tChoose z QNR(Jacobi Symbol +1)")
    print("\t-Candidates of z : ")

    choose_qnr(N,p,q)

    z = input("\tChoose z(QNR, Jacobi Symbol +1) :")

    print("\t Public key  : ",N,z)
    print("\t Private key  : ",p,q)

    plaintxt = input("- Input plain text :")
    #bin_str = bin(int(binascii.hexlify(plaintxt), 16))


    bin_str = bin(int(plaintxt, 2))
    tmp1 = bin_str[2:]

    print("\t Binary bit string of ", plaintxt, "is ",bin_str[2:])

    encryption(bin_str,N,p,q,z,ciphertxt)
    decrypttxt = decryption(ciphertxt,p,q)
    cipher1 = ciphertxt
    ciphertxt = []

#second cipher
    plaintxt2 = input("- Input second plain text :")
    # bin_str = bin(int(binascii.hexlify(plaintxt), 16))

    bin_str = bin(int(plaintxt2, 2))
    tmp2 = bin_str[2:]

    print("\t Binary bit string of ", plaintxt2, "is ", bin_str[2:])

    encryption(bin_str, N, p, q, z, ciphertxt)
    decrypttxt = decryption(ciphertxt, p, q)
    cipher2 = ciphertxt
    ciphertxt = []

    addition = add(cipher1, cipher2, N)
    decrypttxt = decryption(addition, p, q)
    print(int(tmp1, 2))
    print(int(tmp2, 2))
    #test = bool(tmp1) ^ bool(tmp2)
    #test = xor(bool(tmp1), bool(tmp2))
    #test = bin(tmp1 ^ tmp2)
    tst = int(tmp1, 2) ^ int(tmp2, 2)
    print('\nModulo 2 Addition: ', tst)

    #encryption(bin(tst), N, p, q, z, ciphertxt)
    #decrypttxt = decryption(ciphertxt, p, q)

    print("\n\n== Result ==")
    #ch = input("\To Continue press Y:")
    #if (ch == 'Y') or (ch == 'y'):
    #    bin2str(decrypttxt)
    #else:
    #    return

def int_str_to_chr_str(int_str):
    res = []
    for pair in zip(int_str[::2], int_str[1::2]):
        number = int("".join(pair))

        if number <= 26:
            number += 96

        res.append(chr(number))

    return "".join(res)
    
def main():
    bin2str(None)

#    print int_str_to_chr_str("1920012532082114071825463219200125320615151209190846")
    
if __name__=="__main__":
    main()

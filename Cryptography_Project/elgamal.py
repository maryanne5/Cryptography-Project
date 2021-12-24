import random
import math
import sys

def gen_key(bits, zekerheid):
    p = zoek_wortel(bits, zekerheid)
    g = zoek_primitive_wortel(p)
    g = pow(g, 2, p)
    x = random.randint(1, (p - 1) // 2)
    h = pow(g, x, p)
    publicKey = PublicKey(p, g, h, bits)
    privateKey = PrivateKey(p, g, x, bits)
    return {'privateKey': privateKey, 'publicKey': publicKey}


# solovay-strassen primality test.  tests if num is prime
def SS(num, zekerheid):
    # ensure confidence of t
    for i in range(zekerheid):
        # choose random a between 1 and n-2
        a = random.randint(1, num - 1)
        # if a is not relatively prime to n, n is composite
        if gcd(a, num) > 1:
            return False
        # declares n prime if jacobi(a, n) is congruent to a^((n-1)/2) mod n
        if not jacobi(a, num) % num == pow(a, (num - 1) // 2, num):
            return False
    # if there have been t iterations without failure, num is believed to be prime
    return True

#computes the jacobi symbol of a, n
def jacobi( a, n ):
    if a == 0:
        if n == 1:
            return 1
        else:
            return 0
    # property 1 of the jacobi symbol

    elif a == -1:
        if n % 2 == 0:
            return 1
        else:
            return -1
    # if a == 1, jacobi symbol is equal to 1
    elif a == 1:
        return 1
    # property 4 of the jacobi symbol
    elif a == 2:
        if n % 8 == 1 or n % 8 == 7:
            return 1
        elif n % 8 == 3 or n % 8 == 5:
            return -1
    # property of the jacobi symbol:
    # if a = b mod n, jacobi(a, n) = jacobi( b, n )
    elif a >= n:
        return jacobi(a % n, n)
    elif a % 2 == 0:
        return jacobi(2, n)*jacobi(a//2, n)
    # law of quadratic reciprocity
    # if a is odd and a is coprime to n
    else:
        if a % 4 == 3 and n % 4 == 3:
            return -1 * jacobi(n, a)
        else:
            return jacobi(n, a)


def gcd(a, b):
    while b != 0:
        c = a % b
        a = b
        b = c
    return a


def zoek_wortel(bits, zekerheid):
    while 1:
        p = random.randint(2**(bits-2), 2**(bits-1))
        while p % 2 == 0:
            p = random.randint(2 ** (bits - 2), 2 ** (bits - 1))
        while not SS(p, zekerheid):
            p = random.randint(2 ** (bits - 2), 2 ** (bits - 1))
            while p % 2 == 0:
                p = random.randint(2 ** (bits - 2), 2 ** (bits - 1))
        p = p * 2 + 1
        if SS(p, zekerheid):
            return p


def zoek_primitive_wortel(p):
    if p == 2:
        return 1
    p1 = 2
    p2 = (p-1) // p1
    while 1:
        g = random.randint(2, p-1)
        if not (pow(g, (p-1) // p1, p) == 1):
            if not (pow(g, (p-1) // p2, p) == 1):
                return g


class PrivateKey(object):
    def __init__(self, p=None, g=None, x=None, bits=0):
        self.p = p
        self.g = g
        self.x = x
        self.bits = bits


class PublicKey(object):
    def __init__(self, p=None, g=None, h=None, bits=0):
        self.p = p
        self.g = g
        self.h = h
        self.bits = bits


def encode(plaintext, bits):
    byte_array = bytearray(plaintext, 'utf-16')
    z = []
    k = bits//8  # 8 bits per karakter
    j = -1 * k
    num = 0
    for i in range(len(byte_array)):
        if i % k == 0:
            j += k
            num = 0
            z.append(0)
        z[j//k] += byte_array[i]*(2**(8*(i % k)))
    return z


def decode(crypttext, bits):
    bytes_array = []
    k = bits//8
    for num in crypttext:
        for i in range(k):
            temp = num
            for j in range(i+1, k):
                temp = temp % (2**(8*j))
            letter = temp // (2**(8*i))
            bytes_array.append(letter)
            num = num - (letter*(2**(8*i)))
    decodedText = bytearray(b for b in bytes_array).decode('utf-16')
    return decodedText


def encrypt(key, bericht):
    z = encode(bericht, key.bits)
    cipher_pairs = []
    for i in z:
        y = random.randint(0, key.p)
        c = pow(key.g, y, key.p)
        d = (i*pow(key.h, y, key.p)) % key.p
        cipher_pairs.append([c,d])
    encryptedStr = ""
    for pair in cipher_pairs:
        encryptedStr += str(pair[0]) + ' ' + str(pair[1]) + ' '
    return encryptedStr


def decrypt(key, cipher):
    plaintext = []
    cipher_array = cipher.split()
    if not len(cipher_array) % 2 == 0:
        return "Vervormde gegevens"
    for i in range(0, len(cipher_array), 2):
        c = int(cipher_array[i])
        d = int(cipher_array[i+1])
        s = pow(c, key.x, key.p)
        plain = (d*pow(s, key.p-2, key.p)) % key.p
        plaintext.append(plain)
    decryptedtext = decode(plaintext, key.bits)
    decryptedtext = "".join([ch for ch in decryptedtext if ch  != '\x00'])
    return decryptedtext


def test():
    assert(sys.version_info >= (3, 4))
    keys = gen_key(256, 32)
    priv = keys['privateKey']
    pub = keys['publicKey']
    bericht = "Dit is een test"
    versleuteld = encrypt(pub, bericht)
    normaal = decrypt(priv, versleuteld)
    print(bericht)
    print(versleuteld)
    print(normaal)
    return bericht == normaal

'''
assert(sys.version_info >= (3, 4))
keys = gen_key(256, 32)
priv = keys['privateKey']
pub = keys['publicKey']
i = 1
h = []
f = []
while 1:
    bericht = str(i)
    versleuteld = encrypt(pub, bericht)
    h.append(i)
    f.append(versleuteld)
    print(str(i) + ": " + versleuteld)
    i += 1
    if i > 10:
        break
print("Done... Decrypting")
for i in range(f.__len__()):
    decrypted = decrypt(priv, f[i])
    print(h[i], ": ", decrypted)
print(test())
'''
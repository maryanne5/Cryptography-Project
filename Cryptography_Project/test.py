#-*- coding: utf-8 -*-
import LEA
import elgamal
import rabin
import random
import base64
def main():
    
    print("Bob chooses (p,g,a) and publishes it for ALice to use in the El-Gamal EC to encrypt the LEA key")
    print("Alice uses (p,g,a) to encrypt the LEA key \n")
    keys = elgamal.gen_key(256, 32)
    priv = keys['privateKey']
    pub = keys['publicKey']
    bericht = "blacksnakeblacksnake1234"
    versleuteld = elgamal.encrypt(pub, bericht)
    print("Alice encrypted the key successfully using El-Gamal cipher \n")
    print("Alice choses p and q to sign the key using Rabin signature \n")
    p = 37
    q = 7
    print("Alice choses p = \n" ,p)
    print("Alice choses q = \n", q)
    if (not rabin.checkPrime(p,q)):
      p = 31
      q = 23
    
    nRabin = p*q
    resSig, resU = rabin.root(bytes(versleuteld,'utf-8'),p,q)
    encryp = int.from_bytes(bytes(versleuteld,'utf-8'),'big')
    sig2 = resSig**2
    print("Alice signed the key successfully using Rabin signature \n")
    print("Alice send bob the encrypted key\n")
    condVerified = (rabin.h(encryp,resU)) % nRabin == ((sig2)% nRabin)
    print("Bob Verifies that the message was received from Alice-->", condVerified)
    if condVerified:
      print("Bob received the encrypted key\n")
      dec = elgamal.decrypt(priv, versleuteld)
      print("Bob decrypted key using El-GAMAL cipher -->", dec)
    else: 
      print("None verified message")
    print("and he start to encrypt the email message with this key\n")
    input_str='Hello Alice,I am sending you this e-mail to make sure you are alive!'
    print("bob sends a mail to alice with message:\n" + input_str)
    
    pt = bytearray(input_str, "utf8")
    
    #a random 128 bit initial vector
    iv = base64.b16encode(random.getrandbits(128).to_bytes(16, byteorder='little'))
    
    #encryption
    leaCBC = LEA.CBC(True, dec,iv,True)
    ct = leaCBC.update(pt)
    ct += leaCBC.final()

    print("\n\nBob encrypted the email successfully using LEA with CBC mode\n")
    print("Bob send Alice the encrypted email\n")
	
    #decryption
    print("Alice received the encrypted email and she starts decrypting it\n") 
    leaCBC = LEA.CBC(False, dec,iv, True)
    pt = leaCBC.update(ct)
    pt += leaCBC.final()

  
    decrypt_output = pt.decode('utf8')
    print("Alice decrypted the email successfully\n")
    print("The decrypted message is- " + decrypt_output)

    print("Decrypt End")


if __name__ == "__main__":
    main()
   
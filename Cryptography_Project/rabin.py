# -*- coding: utf-8 -*-
"""
Created on Fri Jun 11 13:50:20 2021

@author: USER

"""


def h(m,u):
  C = m + u
  return C

def checkPrime(p,q):
  if p > 1 and q > 1:
    
    # Iterate from 2 to n / 2
    for i in range(2, p):
 
        # If num is divisible by any number between 2 and n / 2, it is not prime
        if (p % i) == 0:
            print("p and q must be prime numbers")
            print("")
            return False
    
    for i in range(2, q):
 
        if (q % i) == 0:
          print("p and q must be prime numbers")
          print("")
          return False

  if (p % 4 == 3) and (q % 4 == 3):
     return True
  else: 
     print("p and q must be equal to 3mod4")
     print("")
     return False
 
    
 
    
import random
def root(m, p, q):
    """Rabin signature algorithm."""
    print("Check if H(m, U) is a square modulo n, if not- we will pick a new pad U")
    while True:
      mInteger = int.from_bytes(m,'big')
            
      u = random.randint(10,1000)
      print("the u is:",u)
      x = int(h(mInteger, u))
      print("The result of H(m,u):", x)

      if pow(x,int((p-1)/2),p) == 1 and pow(x,int((q-1)/2),q) == 1:

          sig = pow(p, q - 2, q) * p * pow(x, int((q + 1) / 4), q)
          sig = (pow(q, p - 2, p) * q * pow(x, int((p + 1) / 4), p) + sig) % (p*q)
          print("sig is %d --> mod n is %d" %(sig, sig%(p*q)))
          if (x) % (p*q) == (sig*sig) % (p*q):
              print("x is a square modulo n")
              print("")
              break
          print("x is not a square modulo n")
          print("")
      else:
        print("need to choose a new u")
        print("")
    print("The signature is [%d,%d]" %(u,sig))
    return sig, u




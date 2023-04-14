import random
import math
from sympy import *
import sympy.ntheory as nt
import hashlib

class Signing():

    def getMessageInSignedFile(self, path):
        selectedElements = []
        with open(path, "r") as f:
            for line in f:
                if '<d>' not in line:
                    selectedElements.append(line)

        selectedElements.pop()
        removeSpacing = selectedElements[-1].replace("\n","")
        selectedElements.pop()
        selectedElements.append(removeSpacing)
        f.close()

        result = ''
        currentGroup = ''

        for line in selectedElements:
            if line == '\n':
                if currentGroup:
                    result += currentGroup.strip() + '\n\n'
                    currentGroup = ''
            else:
                currentGroup += line

        if currentGroup:
            result += currentGroup.strip()

        return (result)    

    def getSignInSignedFile(self, path):
        sign = ""
        char1 = '<d> '
        char2 = ' </d>'

        with open(path, "r") as f:
            for line in f:
                if '<d>' in line:
                    sign = line
        
        result = sign[sign.find(char1)+4 : sign.find(char2)]
        return result

    def writeSignInFile(self,path, messageSigned, message):
        check = False
        file = open("signed_message.txt", "w+")
        file.writelines(message)
        file.close()

        with open(path, 'r') as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            if line.startswith("<d>"):
                lines[i] = messageSigned
                check = True
                break

        if check == True:
            with open(path, 'w') as f:
                f.writelines(lines)
        else:
            file = open(path, "a+")
            file.seek(0)
            file.write("\n"+"\n"+messageSigned)
    
    def gcd(self,a, b):
        while b != 0:
            a, b = b, a % b
        return a  

    def extendedGcd(self,a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            gcd, x, y = self.extendedGcd(b % a, a)
            return (gcd, y - (b // a) * x, x)
        
    def primeGenerator(self):
        while True:
            result = random.randint(0, 100000000)
            if nt.isprime(result):
                return result
            
    def isPrime(self, n):
        if n <= 1:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True
    
    def saveKeyToFile(self,p,q,n,phi,e,d):

        filePrivateKey = open("./RSAKey/key.pri","w")
        filePublicKey = open("./RSAKey/key.pub", "w")

        filePrivateKey.write("Parameter yang digunakan untuk pembangkitan private key:\n")
        filePrivateKey.write("p: " + str(p) + ", " + "q: " + str(q) + "\n")
        filePrivateKey.write("n: " + str(n) + ", " + "phi: " + str(phi) + "\n")
        filePrivateKey.write("")
        filePrivateKey.write("--------------------------------------------------------\n")
        filePrivateKey.write("")
        filePrivateKey.write("Private Key:\n")
        filePrivateKey.write("("+str(d) + ", " + str(n)+")")

        filePublicKey.write("Parameter yang digunakan untuk pembangkitan public key:\n")
        filePublicKey.write("p: " + str(p) + ", " + "q: " + str(q) + "\n")
        filePublicKey.write("n: " + str(n) + ", " + "phi: " + str(phi) + "\n")
        filePublicKey.write("")
        filePublicKey.write("-------------------------------------------------------\n")
        filePublicKey.write("")
        filePublicKey.write("Public Key:\n")
        filePublicKey.write("("+str(e) + ", " + str(n)+")")

        filePrivateKey.close()
        filePublicKey.close()
        
    def generateKeyPair(self):
        p  = self.primeGenerator()
        q = self.primeGenerator()

        n = p * q 
        phi = (p-1) * (q-1)
        e = random.randrange(1, phi)

        g = gcd(e, phi)
        
        while (g != 1):
            e = random.randrange(1, phi)
            g = gcd(e, phi)

        d = self.extendedGcd(e, phi)[1]

        self.saveKeyToFile(p,q,n,phi,e,d)

        return ((e, n), (d, n))
    
    def encrypt(self, plaintext, privateKey):
        d, n = privateKey
        sizeBlock = math.ceil(n.bit_length() / 8)
        plainBlocks = [bytes.fromhex('00') + plaintext[i:i+sizeBlock-1] for i in range(0, len(plaintext), sizeBlock-1)]

        padLength = sizeBlock - len(plainBlocks[-1])
        if padLength:
            plainBlocks[-1] = bytes.fromhex('00') * padLength + plainBlocks[-1]

        plainBlocksCombine = [int.from_bytes(byte, byteorder='big') for byte in plainBlocks]

        cipherBlocks = [pow(block, d, n) for block in plainBlocksCombine]
        cipherBlocksCombine = [block.to_bytes(length=sizeBlock, byteorder='big') for block in cipherBlocks]

        ciphertext = b''.join(cipherBlocksCombine)
        ciphertext += padLength.to_bytes(length=4, byteorder='big')

        return ciphertext.hex()

    def decrypt(self,ciphertext, publicKey):
        e, n = publicKey
        blocksize = (n.bit_length() + 7) // 8

        cipherBlocks, padding = ciphertext[:-4], int.from_bytes(ciphertext[-4:], byteorder='big')
        cipherBlocks = [int.from_bytes(cipherBlocks[i:i+blocksize], byteorder='big') for i in range(0, len(cipherBlocks), blocksize)]

        plainBlocks = [pow(c, e, n).to_bytes(length=blocksize, byteorder='big') for c in cipherBlocks]
        plainBlocks[-1] = plainBlocks[-1][padding:]

        plaintext = b''.join(block[1:] for block in plainBlocks)

        return plaintext.hex()
        
    def sha3(self,message):
        hashedMessage = hashlib.sha3_256(message.encode("latin-1")).hexdigest()
        return hashedMessage

    def generateSignMessage(self, path, privateKey):
        with open(path, "r") as f:
            message = f.read()
        
        messageDigest = self.sha3(message)
        messageDigest = bytes.fromhex(messageDigest)
        sign = self.encrypt(messageDigest, privateKey)

        writtenSigned = "<d> " + sign + " </d>"

        self.writeSignInFile("signed_message.txt",writtenSigned, message)
        
        return sign 
    
    def validateSignedMessage(self,path, publicKey):
        message = self.getMessageInSignedFile(path)
        sign = self.getSignInSignedFile(path)

        if sign == None or sign == "":
            return False

        signHex = bytes.fromhex(sign)

        return self.sha3(message) == self.decrypt(signHex, publicKey)
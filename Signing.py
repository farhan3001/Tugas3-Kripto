import random
from sympy import *
import sympy.ntheory as nt
import hashlib
import gzip
import pickle

class Signing():
    def getMessageInSignedFile(self, path):
        with open(path, 'r') as file:
            lines = file.readlines()

        prefix = "<d>"    

        lines = [line for line in lines if not line.startswith(prefix)]
        lines.pop()

        lineLast = lines[-1]
        lineLast = lineLast.strip('\n')

        lines.pop()
        lines.append(lineLast)

        return ''.join(lines)

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
            file.write("\n\n"+messageSigned)

    def compressRSA(self, ciphertext):
        ciphertextBytes = pickle.dumps(ciphertext)
        compressed_bytes = gzip.compress(ciphertextBytes)
        return compressed_bytes

    def decompressRSA(self, compressedBytes):
        ciphertextBytes = gzip.decompress(compressedBytes)
        ciphertext = pickle.loads(ciphertextBytes)
        return ciphertext
    
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
        d = privateKey[0]
        n = privateKey[1]
        ciphertext = [pow(ord(char), d, n) for char in plaintext]
        print(ciphertext)
        print("")

        ciphertext =self.compressRSA(ciphertext)

        return ciphertext.hex()


    def decrypt(self,ciphertext, publicKey):
        e = publicKey[0]
        n = publicKey[1]

        ciphertext = bytes.fromhex(ciphertext)
        ciphertext = self.decompressRSA(ciphertext)

        plaintext = [chr(pow(char, e, n)) for char in ciphertext]
        return ''.join(plaintext)
        
            
    def sha3(self,message):
        messageBytes = message.encode('utf-8')
        hashObject = hashlib.sha3_256()
        hashObject.update(messageBytes)
        return hashObject.hexdigest()

    def generateSignMessage(self, path, privateKey):
        with open(path, "r") as f:
            message = f.read()

        sign = self.encrypt(message,privateKey)

        writtenSigned = "<d> " + sign + " </d>"

        self.writeSignInFile("signed_message.txt",writtenSigned, message)
        
        return sign
    
    def validateSignedMessage(self,path, publicKey):
        message = self.getMessageInSignedFile(path)
        sign = self.getSignInSignedFile(path)

        if sign == None or sign == "":
            return False

        messageDecrypted = self.decrypt(sign, publicKey)

        return message == messageDecrypted

from Crypto.Util.number import getPrime, getRandomRange, GCD, inverse
"""
class RSA:



    def KeyGen(l):
        l=int(l/2)
        p = getPrime(l)
        q = getPrime(l)
        n = p*q
        phai_n = (p-1)*(q-1)

        gcd = 0
        e = 0
        while gcd != 1:
            e = getRandomRange(2,phai_n-1)
            gcd = GCD(e, phai_n)
        d = inverse(e,phai_n)  
        
        return n,e, d


    def Encrypt(plaintext, public_key):
        n,e = public_key
        x = plaintext

        assert x<n and x>0, "ERROR, plaintext is out of range!"
        p = pow(x,e)
        return p%n

    def Decrypt(ciphertext, private_key,n):
        assert ciphertext<n and ciphertext>0, "ERROR, cipherext is out of range!"
        y = pow(ciphertext,private_key)
        return y%n
    n,e, d = KeyGen(2048)
    p =(n,e)
    y = Encrypt(d,p)
    print(y)
    z = Decrypt(y,d,n)
    print(z)

  """
from Crypto.Util.number import getPrime, getRandomRange, GCD, inverse


class RSA:
    def __init__(self, key_size):
        self.key_size = key_size
        self.n, self.e, self.d = self.KeyGen(key_size)

    def KeyGen(self, l):
        l = int(l // 2)
        p = getPrime(l)
        q = getPrime(l)
        self.n = p * q
        phi_n = (p - 1) * (q - 1)

        gcd = 0
        e = 0
        while gcd != 1:
            e = getRandomRange(2, phi_n - 1)
            gcd = GCD(e, phi_n)

        d = inverse(e, phi_n)
        return self.n, e, d

    def Encrypt(self, plaintext):
        """Encrypts the provided plaintext using the RSA public key."""
        x = int(plaintext.encode('utf-8').hex(), 16)  # Convert text to integer
        assert x < self.n and x > 0, "ERROR, plaintext is out of range!"
        n=self.n
        e=self.e
       
        cipher = self.exp_func(x,e,n)
        cipher = cipher %n
        return cipher

    def Decrypt(self, ciphertext):
        """Decrypts the provided ciphertext using the RSA private key."""
        n=self.n
        d=self.d
        plain =self.exp_func(ciphertext,d,n)
        try:
        # Attempt UTF-8 decoding first
            return plain.to_bytes((plain.bit_length() + 7) // 8, 'big').decode('utf-8')
        except UnicodeDecodeError:
        # Fallback to Latin-1 encoding if UTF-8 fails
            return plain.to_bytes((plain.bit_length() + 7) // 8, 'big').decode('latin-1')
        
    def exp_func(self, x, y,n):
        exp = bin(y)
        value = x

        for i in range(3, len(exp)):
            value = value * value%n
            if(exp[i:i+1]=='1'):
                value = value*x%n
        return value
    
    def read_and_encrypt_file(self, filename):
        """Reads a text file and encrypts its contents."""
        with open(filename, 'r') as f:
            plaintext = f.read()
            messagebit = len(plaintext)*8
            nloops = round(messagebit / key_size)
            ciphertext = []

        for i in range(nloops):
            
            ciphertext=self.Encrypt(plaintext[i:i+round(nloops/8)])
            if i ==1:
                with open(filename + ".enc", 'w') as f:
                    ciphertextstr = str(ciphertext)
                    f.write(ciphertextstr)
            else:
                with open(filename + ".enc", 'a') as f:
                    f.write("-----------")
                    ciphertextstr = str(ciphertext)
                    f.write(ciphertextstr)
                    
        print(f"File '{filename}' encrypted successfully to '{filename}.enc'")

    def read_and_decrypt_file(self, filename):
        decrypted = []
        with open(filename, 'r') as f:
            ciphertext = f.read()
            split_text = ciphertext.split("-----------")
            for i in split_text:
                
                decrypted.append(self.Decrypt(int(i)))
                print(decrypted)
            
        
        


if __name__ == "__main__":
    key_size = 4000
    rsa = RSA(key_size)

    filename = "tobeenc.txt"
    rsa.read_and_encrypt_file(filename)
    rsa.read_and_decrypt_file(filename+".enc")


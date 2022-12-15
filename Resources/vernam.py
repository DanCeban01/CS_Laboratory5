def vernam(plain_text,key):

    
    plain_text=plain_text.replace(" ","")
    key=key.replace(" ","")
    plain_text=plain_text.lower()
    key=key.lower()
    
    if(len(plain_text)!=len(key)):
        print("Lengths are different")
        
    else:
        cipher_text=""
        
        for i in range(len(plain_text)):
            k1=ord(plain_text[i])-97
            k2=ord(key[i])-97
            s=chr((k1+k2)%26+97)
            cipher_text+=s
        print("Enrypted message is: ",cipher_text)


plain_text=input("Enter the message: ")
key=input("Enter the one time pad: ")
vernam(plain_text,key)

def vernam(cipher_text,key):

    cipher_text=cipher_text.lower()
    key=key.lower()
    cipher_text=cipher_text.replace(" ","")
    key=key.replace(" ","")
    
    plain_text=""
    
    for i in range(len(cipher_text)):
        k1=ord(cipher_text[i])-97
        k2=ord(key[i])-97
        s=chr((((k1-k2)+26)%26)+97)
        plain_text+=s
    print("Decrypted message is: ",plain_text)


plain_text=input("Enter the message to be decrypted: ")
key=input("Enter the one time pad: ")
vernam(plain_text,key)
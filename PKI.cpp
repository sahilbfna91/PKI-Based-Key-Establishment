#include<bits/stdc++.h>
#include<openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include<chrono>
#include <openssl/engine.h>
using namespace std::chrono;
using namespace std;
EVP_PKEY *pubkey;
 unsigned char *outl;
int EncodingSize(int File_Size)
{
int temp=File_Size/48;
return (File_Size/48)*65+((File_Size-(temp*48))/3)*4+((File_Size-temp*48)%3)*5;
}
int Decode_cipher_base64(unsigned char* encodecipher,unsigned char* decodedcipher,int eclen)
{

  EVP_ENCODE_CTX* ctx=EVP_ENCODE_CTX_new();
  int len;
  EVP_DecodeInit(ctx);
  EVP_DecodeUpdate(ctx,decodedcipher,&len,encodecipher,eclen);
  int temp=len;
  EVP_DecodeFinal(ctx,decodedcipher,&len);
  temp+=len;
  EVP_ENCODE_CTX_free(ctx);
  return temp;


}
void Encode_cipher_base64(unsigned char *cipher,unsigned char *encodedcipher,int clen)
{


EVP_ENCODE_CTX*  ctx;
ctx=EVP_ENCODE_CTX_new();
int len,temp;
EVP_EncodeInit(ctx);
EVP_EncodeUpdate(ctx,encodedcipher,&len,cipher,clen);
temp=len;
EVP_EncodeFinal(ctx,encodedcipher+len,&len);
temp+=len;
EVP_ENCODE_CTX_free(ctx);
}

unsigned char* AES_enc(const EVP_CIPHER *cipher_type,unsigned char *plaintext,int keylen,int File_Size,int B64_Encoding_size,unsigned char* key)
{
unsigned char *iv=new unsigned char[16];
RAND_bytes(iv,16);//Getting random IV
/*Storing Base64 encoding of Random IV in intermediate file */
fstream IV_file;
int enivlen=EncodingSize(16);
unsigned char* encodediv=new unsigned char[enivlen];
Encode_cipher_base64(iv, encodediv,16);
IV_file.open("iv.txt",ios::out);
IV_file<<encodediv;

unsigned char *ciphertext=new unsigned char[File_Size+16];
EVP_CIPHER_CTX *ctx;//EVP data structure for encryption/decryption
unsigned char *encodedcipher=new unsigned char[B64_Encoding_size+100];
/*Initializing parameters*/
ctx=EVP_CIPHER_CTX_new();
const unsigned char* salt=(const unsigned char*)"123456";//Getting user generated passwords
                                                            //that take user passphrase generate key of reuired size
EVP_EncryptInit_ex(ctx,cipher_type,NULL,key,iv);//initializing the data structure ctx
int inlen=File_Size,len;

EVP_EncryptUpdate(ctx,ciphertext,&len,plaintext, inlen);//Encrypting teh data
EVP_EncryptFinal_ex(ctx,ciphertext+len,&len);


EVP_CIPHER_CTX_free(ctx);
/*Converting the cipher text in Base64 and storing it in intermediate file*/
fstream Ciphertext_encoded_file;
Encode_cipher_base64(ciphertext,encodedcipher,File_Size);//Encoding in Bse64
return encodedcipher;//writing in the intermediate file
  
}
void AES_dec(const EVP_CIPHER *cipher_type,unsigned char *cipher_text,int clen,int keylen,int File_Size,string outfile,unsigned char* key)
{
  /*Getting the random generated IV at time of encryption from Intermediate file*/
unsigned char *iv=new unsigned char[16];
fstream IV_file;
IV_file.open("iv.txt",ios::in);//Intermediate file containing Encode IV
IV_file>>iv;
int enivlen=EncodingSize(16);
unsigned char *decodeiv=new unsigned char[16];
Decode_cipher_base64(iv,decodeiv,enivlen);//Decoding the IV

unsigned char *plain_text=new unsigned char[File_Size+100];
int len;
const unsigned char* salt=(const unsigned char*)"123456";
EVP_CIPHER_CTX *ctx;
ctx=EVP_CIPHER_CTX_new();


EVP_DecryptInit_ex(ctx,cipher_type,NULL,key,decodeiv);//Initializing  ctx

EVP_DecryptUpdate(ctx,plain_text,&len,cipher_text,clen);//Decryptin the data
EVP_DecryptFinal(ctx,plain_text+len,&len);//Decryptingt the final block 

EVP_CIPHER_CTX_free(ctx);
/*Writing plaintext to file*/
fstream Plaintext_file;
Plaintext_file.open(outfile,ios::out);
Plaintext_file<<plain_text;
}



X509* CA()
{
EVP_PKEY *pkey;
pkey=EVP_PKEY_new();
RSA *rsa=RSA_new();
BIGNUM *e=BN_new();
BN_generate_prime_ex(e,16,1,NULL,NULL,NULL);
RSA_generate_key_ex(rsa,2048,e,NULL);
EVP_PKEY_assign_RSA(pkey,rsa);
X509* x509;
x509=X509_new();
ASN1_INTEGER_set(X509_get_serialNumber(x509),1);
X509_gmtime_adj(X509_get_notBefore(x509), 0);
X509_gmtime_adj(X509_get_notAfter(x509), (long) 60*60*24*365);
X509_set_pubkey(x509,pkey);

X509_NAME *name;
name=(X509_NAME*)"sahil";
X509_sign(x509,pkey,EVP_sha1());
FILE *f;
f=fopen("key.pem","wb");
PEM_write_PrivateKey(f,pkey,EVP_des_ede3_cbc(),(unsigned char*)"sahil",5,NULL,NULL);
fclose(f);
f=fopen("pubkey.pem","wb");
PEM_write_PUBKEY(f,pkey);
fclose(f);
f=fopen("Cert.pem","wb");
PEM_write_X509(f,x509);
fclose(f);

f=fopen("pubkey.pem","r");
pubkey=EVP_PKEY_new();
PEM_read_PUBKEY(f,&pubkey,NULL,NULL);

return x509;
    
}

unsigned char * Reciever(X509* x509,unsigned char *encrypted,string s,int BS)
{
  unsigned char * sess_Key=(unsigned char *)"123456789123456789123456";
if(s=="Verify")
 {
   if (X509_verify(x509,pubkey)==1)
  cout<<"R:Certificate Succesfully verified by reciever\n";
  else cout<<"R:Certificate not Succesfully verified\n";
 }

else
{ 
  unsigned char* decodecipher=new unsigned char[BS];
  int cplen=Decode_cipher_base64(encrypted,decodecipher,BS);
  string outfile="out.txt";//file to store the decrypted
  AES_dec(EVP_aes_192_ctr(),decodecipher,cplen,(192)/8,cplen,outfile,sess_Key);
  cout<<"R:File decrypted\n";
  }
 
return sess_Key;
}




void sender()
{
cout<<"S:Requesting CA for Certificate\n";
X509* x509=CA();
cout<<"S:Recieved\n";
cout<<"Sending Certificate to Reciever\n";
unsigned char * skey=Reciever(x509,NULL,"Verify",0);
cout<<"S:Recieved session key\n";
  string infile="inpkb4.txt";//change input file name here
  fstream msg_file;
  msg_file.open(infile,ios::in);
  msg_file.seekg(0, ios::end);
  int File_Size = msg_file.tellg();
  int B64_Encoding_size=EncodingSize(File_Size);//Getting Base64 Encoding size for the msg
  msg_file.close();

  const EVP_CIPHER *cipher_type;
  fstream msg_file1;
  msg_file1.open(infile,ios::in);
  unsigned char *Msg= new unsigned char[File_Size];
  msg_file1>>Msg;
  msg_file1.close();
  cout<<"S:Sender Encrypting file\n";
  unsigned char* encrypted=AES_enc(EVP_aes_192_ctr(),Msg,(192)/8,File_Size,B64_Encoding_size,skey);
  cout<<"Encrypted\n";
  cout<<"S: Sending file to reciever to decrypted\n";
  Reciever(x509,encrypted,"decrypt",B64_Encoding_size);

}


int main()
{

sender();
}
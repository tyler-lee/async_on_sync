#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <openssl/aes.h>

#define AOS_TAG_SIZE AES_BLOCK_SIZE
#define AOS_KEY_SIZE (AES_BLOCK_SIZE*2)
#define AOS_BLOCK_SIZE AES_BLOCK_SIZE

//https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
//Return ciphertext_len
int encrypt_aes_256_gcm(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
	unsigned char *ciphertext, unsigned char *tag);

//https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
//Return plaintext_len
int decrypt_aes_256_gcm(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
	int iv_len, unsigned char *plaintext);

//https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
//Return ciphertext_len
int encrypt_aes_256_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);

//https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
//Return plaintext_len
int decrypt_aes_256_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);

#endif //! __CRYPTO_H__

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <openssl/aes.h>

#define AOS_TAG_SIZE		AES_BLOCK_SIZE
#define AOS_KEY_SIZE		(AES_BLOCK_SIZE*2)
#define AOS_BLOCK_SIZE		AES_BLOCK_SIZE
#define AOS_CMAC_SIZE		AOS_BLOCK_SIZE
#define AOS_HMAC_SIZE		32	//For Sha256

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

//Return mac_len
size_t cmac_aes_256_cbc_sign(const void *msg, size_t msg_len, unsigned char *key, size_t key_len, unsigned char *mac);

//Reture 1 -- valid mac; 0 -- invalid mac;
int cmac_aes_256_cbc_verify(const unsigned char *mac, size_t mac_len, const void *msg, size_t msg_len, unsigned char *key, size_t key_len);

//Return mac_len
size_t hmac_sha256_sign(const void *msg, size_t msg_len, unsigned char *key, size_t key_len, unsigned char *mac);
size_t hmac_sha256_sign_digestsign(const void *msg, size_t msg_len, unsigned char *key, size_t key_len, unsigned char *mac);

//Reture 1 -- valid mac; 0 -- invalid mac;
int hmac_sha256_verify(const unsigned char *mac, size_t mac_len, const void *msg, size_t msg_len, unsigned char *key, size_t key_len);
int hmac_sha256_verify_digestsign(const unsigned char *mac, size_t mac_len, const void *msg, size_t msg_len, unsigned char *key, size_t key_len);

#endif //! __CRYPTO_H__

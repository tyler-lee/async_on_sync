#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/hmac.h>
//#include <openssl/err.h>	//ERR_print_errors_fp
#include "Crypto.h"

void handleErrors(void)
{
  //ERR_print_errors_fp(stderr);
  abort();
}

//https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
//Return ciphertext_len
int encrypt_aes_256_gcm(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
	unsigned char *ciphertext, unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) handleErrors();

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(aad != NULL && aad_len != 0) if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AOS_TAG_SIZE, tag)) handleErrors();

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

//https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
//Return plaintext_len
int decrypt_aes_256_gcm(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
	int iv_len, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) handleErrors();

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(aad != NULL && aad_len != 0) if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AOS_TAG_SIZE, tag)) handleErrors();

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}

//https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
//Return ciphertext_len
int encrypt_aes_256_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

//https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
//Return plaintext_len
int decrypt_aes_256_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

//Return mac_len
size_t cmac_aes_256_cbc_sign(const void *msg, size_t msg_len, unsigned char *key, size_t key_len, unsigned char *mac)
{
	size_t mac_len;
	CMAC_CTX *ctx;
	if(!(ctx = CMAC_CTX_new())) handleErrors();

	if(1 != CMAC_Init(ctx, key, key_len, EVP_aes_256_cbc(), NULL)) handleErrors();
	if(1 != CMAC_Update(ctx, msg, msg_len)) handleErrors();
	if(1 != CMAC_Final(ctx, mac, &mac_len)) handleErrors();

	CMAC_CTX_free(ctx);
	return mac_len;
}

//Reture 1 -- valid mac; 0 -- invalid mac;
int cmac_aes_256_cbc_verify(const unsigned char *mac, size_t mac_len, const void *msg, size_t msg_len, unsigned char *key, size_t key_len)
{
	unsigned char tmp_mac[EVP_MAX_MD_SIZE];
	size_t tmp_mac_len = cmac_aes_256_cbc_sign(msg, msg_len, key, key_len, tmp_mac);
	const size_t len = mac_len < tmp_mac_len ? mac_len : tmp_mac_len;
	//CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
	return !CRYPTO_memcmp(mac, tmp_mac, len);
}

//Return mac_len
size_t hmac_sha256_sign(const void *msg, size_t msg_len, unsigned char *key, size_t key_len, unsigned char *mac)
{
	unsigned int mac_len;
	HMAC_CTX *ctx;

	if(!(ctx = HMAC_CTX_new())) handleErrors();
	if(1 != HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL)) handleErrors();
	if(1 != HMAC_Update(ctx, (const unsigned char*)msg, msg_len)) handleErrors();
	if(1 != HMAC_Final(ctx, mac, &mac_len)) handleErrors();
	HMAC_CTX_free(ctx);

	return mac_len;
}
size_t hmac_sha256_sign_digestsign(const void *msg, size_t msg_len, unsigned char *key, size_t key_len, unsigned char *mac)
{
	size_t mac_len;
	EVP_MD_CTX* ctx = NULL;
	//const EVP_MD* md = NULL;
	EVP_PKEY *pkey = NULL;

	if(!(pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len))) handleErrors();
	//OpenSSL_add_all_digests();
	//if(!(md = EVP_get_digestbyname("SHA256"))) handleErrors();
	//if(1 != EVP_DigestInit_ex(ctx, md, NULL)) handleErrors();

	if(!(ctx = EVP_MD_CTX_create())) handleErrors();

	//if(1 != EVP_DigestSignInit(ctx, NULL, md, NULL, pkey)) handleErrors();
	if(1 != EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey)) handleErrors();
	if(1 != EVP_DigestSignUpdate(ctx, msg, msg_len)) handleErrors();
	if(1 != EVP_DigestSignFinal(ctx, mac, &mac_len)) handleErrors();

	if(ctx) EVP_MD_CTX_destroy(ctx);
	if(pkey) EVP_PKEY_free(pkey);

	return mac_len;
}

//Reture 1 -- valid mac; 0 -- invalid mac;
int hmac_sha256_verify(const unsigned char *mac, size_t mac_len, const void *msg, size_t msg_len, unsigned char *key, size_t key_len)
{
	unsigned char tmp_mac[EVP_MAX_MD_SIZE];
	size_t tmp_mac_len = hmac_sha256_sign(msg, msg_len, key, key_len, tmp_mac);
	const size_t len = mac_len < tmp_mac_len ? mac_len : tmp_mac_len;
	//CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
	return !CRYPTO_memcmp(mac, tmp_mac, len);
}
//Reture 1 -- valid mac; 0 -- invalid mac;
int hmac_sha256_verify_digestsign(const unsigned char *mac, size_t mac_len, const void *msg, size_t msg_len, unsigned char *key, size_t key_len)
{
	unsigned char tmp_mac[EVP_MAX_MD_SIZE];
	size_t tmp_mac_len = hmac_sha256_sign_digestsign(msg, msg_len, key, key_len, tmp_mac);
	const size_t len = mac_len < tmp_mac_len ? mac_len : tmp_mac_len;
	//CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
	return !CRYPTO_memcmp(mac, tmp_mac, len);
}

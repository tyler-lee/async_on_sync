#include <stdarg.h>
#include <stdio.h>      /* vsnprintf stderr*/
#include <string.h>	//memcpy
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
//#include <openssl/err.h>	//ERR_print_errors_fp

#include "PublicEnclave.h"
#include "PublicEnclave_t.h"  /* print_string */
#include "sgx_trts.h"

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void handleErrors(void)
{
  //ERR_print_errors_fp(stderr);
  abort();
}

//https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
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
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

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
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) handleErrors();

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

//https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
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
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) handleErrors();

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

void aos_verify() {
	//TODO: it seems intel-sgx-ssl does NOT support EVP !!!
	//EVP_CIPHER_CTX *ctx;
	//if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	//EVP_CIPHER_CTX_free(ctx);

	ocall_print_string("in enclave: aos_verify\n");
	return;
}

void aos_encrypt(aos_key_t pkey) {
    AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
    unsigned char iv[AES_BLOCK_SIZE];        // init vector
    unsigned char* encrypt_string;
    unsigned char* decrypt_string;
    unsigned int len;        // encrypt length (in multiple of AES_BLOCK_SIZE)
    unsigned int i;

    // set the encryption length
    const char* input_string = "Hello World\n今天天气还可以，测试一下在enclave里调用OpenSSL\n";
    len = ((strlen(input_string)+1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

    // alloc encrypt_string
    encrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (encrypt_string == NULL) {
        printf("Unable to allocate memory for encrypt_string\n");
        //exit(-1);
    }
    // alloc decrypt_string
    decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (decrypt_string == NULL) {
        printf("Unable to allocate memory for decrypt_string\n");
        //exit(-1);
    }

    // Generate AES 128-bit key
    for (i=0; i<16; ++i) {
        key[i] = 32 + i;
    }

    // Set encryption key
    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
#if 1
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {
        printf("Unable to set encryption key in AES\n");
        //exit(-1);
    }
    // encrypt (iv will change)
    AES_cbc_encrypt((unsigned char*)input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);

#else
	EVP_CIPHER_CTX *ctx;
	int outlen;
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	//if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) handleErrors();
	//if(1 != EVP_EncryptUpdate(ctx, decrypt_string, &outlen, (unsigned char*)input_string, len)) handleErrors();
	//ciphertext_len = outlen;
	//if(1 != EVP_EncryptFinal_ex(ctx, decrypt_string + outlen, &outlen)) handleErrors();
	//ciphertext_len += outlen;
	EVP_CIPHER_CTX_free(ctx);
#endif

    // Set decryption key
    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_decrypt_key(key, 128, &aes) < 0) {
        printf("Unable to set decryption key in AES\n");
        //exit(-1);
    }
    // decrypt
    AES_cbc_encrypt(encrypt_string, decrypt_string, len, &aes, iv,
            AES_DECRYPT);

    // print
    printf("input_string = %s\n", input_string);
    printf("encrypted string = ");
    for (i=0; i<len; ++i) {
        printf("%02x", encrypt_string[i]);
    }
    printf("\n");
    printf("decrypted string = %s\n", decrypt_string);


	free(encrypt_string);
	free(decrypt_string);
}


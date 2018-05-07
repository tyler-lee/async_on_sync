#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>	//memcpy
#include <stdlib.h>
#include <openssl/aes.h>

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


void aos_verify() {
	ocall_print_string("in enclave: aos_verify\n");
	return;
}

/*
# define AES_ENCRYPT     1
# define AES_DECRYPT     0
# define AES_BLOCK_SIZE 16
int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const AES_KEY *key,
                     unsigned char *ivec, const int enc);
void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        unsigned char ivec[AES_BLOCK_SIZE],
                        unsigned char ecount_buf[AES_BLOCK_SIZE],
                        unsigned int *num);
*/
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

    // Generate AES 128-bit key
    for (i=0; i<16; ++i) {
        key[i] = 32 + i;
    }

    // Set encryption key
    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {
        printf("Unable to set encryption key in AES\n");
        //exit(-1);
    }

    // alloc encrypt_string
    encrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (encrypt_string == NULL) {
        printf("Unable to allocate memory for encrypt_string\n");
        //exit(-1);
    }

    // encrypt (iv will change)
    AES_cbc_encrypt((unsigned char*)input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);

    // alloc decrypt_string
    decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (decrypt_string == NULL) {
        printf("Unable to allocate memory for decrypt_string\n");
        //exit(-1);
    }

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

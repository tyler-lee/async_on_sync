#include <stdarg.h>
#include <stdio.h>      /* vsnprintf stderr*/
#include <string.h>	//memcpy
#include <stdlib.h>
#include "PublicEnclave.h"
#include "PublicEnclave_t.h"  /* print_string */
#include "sgx_trts.h"
#include "Crypto.h"

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

void test_cipher() {
	char plaintext[68] = "Hello world. 这个世界真美好！！！！！&&&&&&&";
	int plaintext_len = 68;
	char decryptedtext[100];
	char ciphertext[100];
	int ciphertext_len = 100;
	unsigned char key[AOS_KEY_SIZE];
	unsigned char iv[AOS_BLOCK_SIZE];
	int iv_len = AOS_BLOCK_SIZE;
	unsigned char tag[AOS_TAG_SIZE];

	sgx_read_rand(key, AOS_KEY_SIZE);
	sgx_read_rand(iv, AOS_BLOCK_SIZE);

	printf("============= aes_256_cbc ===============\n");
	printf("plaintext: %s\n", plaintext);
	ciphertext_len = encrypt_aes_256_cbc((unsigned char*)plaintext, strlen(plaintext), key, iv, (unsigned char*)ciphertext);
	plaintext_len = decrypt_aes_256_cbc((unsigned char*)ciphertext, ciphertext_len, key, iv, (unsigned char*)decryptedtext);
	decryptedtext[plaintext_len] = '\0';
	printf("decryptedtext: %s\n", decryptedtext);

	printf("============= aes_256_gcm: with empty aad ===============\n");
	printf("plaintext: %s\n", plaintext);
	ciphertext_len = encrypt_aes_256_gcm((unsigned char*)plaintext, strlen(plaintext), NULL, 0, key, iv, iv_len, (unsigned char*)ciphertext, tag);
	plaintext_len = decrypt_aes_256_gcm((unsigned char*)ciphertext, ciphertext_len, NULL, 0, tag, key, iv, iv_len, (unsigned char*)decryptedtext);
	decryptedtext[plaintext_len] = '\0';
	printf("decryptedtext: %s\n", decryptedtext);

	printf("============= aes_256_gcm: with aad ===============\n");
	unsigned char aad[100];
	int aad_len = 100;
	sgx_read_rand(aad, aad_len);
	printf("plaintext: %s\n", plaintext);
	ciphertext_len = encrypt_aes_256_gcm((unsigned char*)plaintext, strlen(plaintext), aad, aad_len, key, iv, iv_len, (unsigned char*)ciphertext, tag);
	plaintext_len = decrypt_aes_256_gcm((unsigned char*)ciphertext, ciphertext_len, aad, aad_len, tag, key, iv, iv_len, (unsigned char*)decryptedtext);
	decryptedtext[plaintext_len] = '\0';
	printf("decryptedtext: %s\n", decryptedtext);
}

void test_mac() {
	char plaintext[68] = "Hello world. 这个世界真美好！！！！！&&&&&&&";
	int plaintext_len = 68;
	unsigned char mac[AOS_MAX_MAC_SIZE];
	int mac_len = AOS_MAX_MAC_SIZE;
	unsigned char key[AOS_KEY_SIZE];
	int key_len = AOS_KEY_SIZE;

	sgx_read_rand(key, AOS_KEY_SIZE);

	printf("============= cmac_aes_256_cbc ===============\n");
	mac_len = cmac_aes_256_cbc_sign(plaintext, plaintext_len, key, key_len, mac);
	if(!cmac_aes_256_cbc_verify(mac, mac_len, plaintext, plaintext_len, key, key_len)) printf("Verify fail\n");
	mac[0]--;
	if(!cmac_aes_256_cbc_verify(mac, mac_len, plaintext, plaintext_len, key, key_len)) printf("Verify success\n");
	else printf("Verify fail\n");


	printf("============= hmac_sha256 ===============\n");
	mac_len = hmac_sha256_sign(plaintext, plaintext_len, key, key_len, mac);
	if(!hmac_sha256_verify(mac, mac_len, plaintext, plaintext_len, key, key_len)) printf("Verify fail\n");

	//printf("============= hmac_sha256_digestsign ===============\n");
	unsigned char mac_ds[AOS_MAX_MAC_SIZE];
	int mac_ds_len = AOS_MAX_MAC_SIZE;
	mac_ds_len = hmac_sha256_sign_digestsign(plaintext, plaintext_len, key, key_len, mac_ds);
	if(!hmac_sha256_verify_digestsign(mac_ds, mac_ds_len, plaintext, plaintext_len, key, key_len)) printf("Verify fail\n");

	//printf("============= Consistent test ===============\n");
	if(mac_len != mac_ds_len || CRYPTO_memcmp(mac, mac_ds, mac_len)) printf("Verify not equal\n");

	mac_ds[0]++;
	if(hmac_sha256_verify_digestsign(mac_ds, mac_ds_len, plaintext, plaintext_len, key, key_len)) printf("Verify fail\n");

	mac_ds[0]--;
	plaintext[0]++;
	if(!hmac_sha256_verify_digestsign(mac_ds, mac_ds_len, plaintext, plaintext_len, key, key_len)) printf("Verify success\n");
	else printf("Verify fail\n");
}

void aos_verify() {
	test_cipher();
	test_mac();
	printf("in enclave: aos_verify\n");
}

void aos_encrypt(aos_key_t pkey) {
	printf("in enclave: aos_encrypt\n");
}


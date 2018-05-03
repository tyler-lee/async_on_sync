#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>	//memcpy

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "../Include/user_types.h"
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

//!!! MUST using volatile, otherwise threads CANNOT sync the latest value !!!
volatile bool b_exit = false;
const int CACHE_LINE_SIZE = 64;
volatile uint8_t ready_flags[CORES_PER_CPU][CACHE_LINE_SIZE];
volatile uint8_t sync_flag = 1;

bool is_all_se_online() {
	for(int i=0; i<CORES_PER_CPU; ++i) {
		if(sync_flag != ready_flags[i][0]) return false;
	}

	return true;
}

void ecall_compute(size_t count, size_t* hitCount, size_t* maxMissCount) {
	b_exit = false;

	ready_flags[0][0] = sync_flag;
	uint64_t hit = 0;
	uint64_t miss = 0;
	uint64_t miss_max = 0;
	do {
		if (is_all_se_online()) {
			sync_flag++;
			//sgx_read_rand((unsigned char*)&sync_flag, 1);
			ready_flags[0][0] = sync_flag;

			//if valid == 1, an exception happened.
			//if(sgx_is_exception_happen()) printf("An AEX happened\n");

			//do jobs: 剩余可用时间为安全时间-此次通信时间（miss_max）,++miss每次消耗1 cycle
			++hit;
			if (miss > miss_max) miss_max = miss;
			miss = 0;
		}
		else {
			++miss;
			//if(miss > 9000) break;
		}
	} while (hit < count);

	if(hit == 0) miss_max = count;
	*hitCount = hit;
	*maxMissCount = miss_max;
	//printf("lhr_exception_count: %zu\n", sgx_get_exception_count());

	b_exit = true;
}

void ecall_seize_core(size_t cpu) {
	assert(cpu < CORES_PER_CPU);
	assert(cpu > 0);

	do {
		ready_flags[cpu][0] = sync_flag;
	} while (!b_exit);
}


//TODO: 还有问题？什么时候让他退出？不能一次成功检测就退出，要在整个计算结束后。怎么区分两种情况
//bool is_all_se_online() {
	//global_command = Cmd_set;
	//while ((cores_ready_flag & CORES_MASK) != CORES_MASK) cores_ready_flag |= 1;

	//size_t miss = 0;
	//do {
		//cores_ready_flag |= 1;

		//if (cores_ready_flag == CORES_MASK) {
			//global_command = Cmd_reset;
			//break;
		//}
		//else {
			//++miss;
			//if(miss > 9000) return false;
		//}
	//} while (true);
	//global_command = Cmd_exit;

	//for(size_t i = 1; i < CORES_PER_CPU; ++i) {
		 //counters_pre[i] = counters[i];
	//}

	//return true;
//}
//bool is_irq_happen() {
	//if(sgx_is_exception_happen()) return true;
	//size_t count = 0;
	//size_t temp = 0;
	//for(size_t i = 1; i < CORES_PER_CPU; ++i) {
		//temp = counters[i] - counters_pre[i];
		//if(temp > count) count = temp;
	//}
	//if(count > 9000) return true;

	//return false;
//}
//void seize_core_helper(size_t cpu) {
	//assert(cpu <= CORES_PER_CPU);
	//assert(cpu > 0);
	//counters[cpu] = 0;
	//size_t cbit = 1 << cpu;

	//do {
		//if (global_command == Cmd_set) {
			//cores_ready_flag |= cbit;
		//}
		//else {
			//cores_ready_flag = 0;
			//++counters[cpu];
		//}
	//} while (global_command != Cmd_exit);
//}

void ecall_empty() {
}
void ecall_empty_ocall() {
	ocall_empty();
}

//测量RSA计算性能
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#if defined(MBEDTLS_FS_IO)
#undef MBEDTLS_FS_IO
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME) && \
    /*defined(MBEDTLS_FS_IO) && */defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"

#include <stdio.h>
#include <string.h>
#endif

#define KEY_SIZE 2048
#define EXPONENT 65537

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||   \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_GENPRIME) ||      \
    /*!defined(MBEDTLS_FS_IO) || */!defined(MBEDTLS_CTR_DRBG_C)
#error message("environment does NOT support")
void measurement_rsa_sign_performance() {
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_RSA_C and/or MBEDTLS_GENPRIME and/or "
           "MBEDTLS_FS_IO and/or MBEDTLS_CTR_DRBG_C not defined.\n");
}
#else
mbedtls_rsa_context rsa;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
int ecall_rsa_sign_init(size_t key_size_in_bit) {
    int ret;
    const char *pers = "rsa_genkey";
	int bSuccess = true;

	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 ) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
		bSuccess = false;
        goto exit;
    }

	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    if( ( ret = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, key_size_in_bit, EXPONENT ) ) != 0 ) {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret );
		bSuccess = false;
        goto exit;
    }

exit:
	if (!bSuccess) {
		mbedtls_rsa_free( &rsa );
		mbedtls_ctr_drbg_free( &ctr_drbg );
		mbedtls_entropy_free( &entropy );
		return -1;
	}

	return 0;
}
int ecall_rsa_sign_do(size_t count) {
    int ret;
	int bSuccess = true;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

	for(int i = 0; i < count; i++) {
		//call rsa sign
		if( ( ret = mbedtls_rsa_pkcs1_sign( &rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 20, hash, buf ) ) != 0 ) {
			mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", -ret );
			bSuccess = false;
			goto exit;
		}
		//for(int i = 0; i < rsa.len; i++ )
			//mbedtls_fprintf( stdout, "%02X%s", buf[i], ( i + 1 ) % 16 == 0 ? "\r\n" : " " );
		//mbedtls_printf( "\n  . Done (created signature)\n\n");
	}

exit:
	if (!bSuccess) {
		mbedtls_rsa_free( &rsa );
		mbedtls_ctr_drbg_free( &ctr_drbg );
		mbedtls_entropy_free( &entropy );
		return -1;
	}

	return 0;
}
int ecall_rsa_sign_destroy() {
	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );

	return 0;
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_RSA_C &&
          MBEDTLS_GENPRIME && MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */

void ecall_loop_for_cycles() {
	volatile size_t i = 0;
	size_t count = 1 << 17;	//about 630000 cycles
	while (++i < count);
}


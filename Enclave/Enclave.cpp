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
void ecall_loop_for_cycles() {
	volatile size_t i = 0;
	size_t count = 1 << 17;	//about 630000 cycles
	while (++i < count);
}


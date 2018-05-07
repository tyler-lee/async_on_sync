#include <thread>
#include <stdio.h>
#include <iostream>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <sys/ioctl.h>

using namespace std;

#include "App.h"
#include "PrivateEnclave_u.h"

#include "../Include/user_types.h"

uint64_t rdtscp() {
#ifdef __linux__
	uint64_t a, d;
	//asm volatile ("xor %%rax, %%rax\n" "cpuid"::: "rax", "rbx", "rcx", "rdx");
	asm volatile ("rdtscp" : "=a" (a), "=d" (d) : : "rcx");
	return (d << 32) | a;
#else
	unsigned int tsc;

	return __rdtscp(&tsc);
#endif
}

//ptr is of type const char*
#define clflush(p) asm volatile("clflush (%0)" : : "r" (p) : "memory")

void sleep_for_cycles(size_t cycles) {
	uint64_t end = rdtscp() + cycles;
	while (rdtscp() < end);
}

//put this at last
void lhr_measurement() {
	system("clear");

#ifdef __USE_ENCLAVE__	 //we need highest priority of FIFO in our method
	printf("In %s:\n", __FUNCTION__);
	set_thread_policy_and_priority(SCHED_FIFO, sched_get_priority_max(SCHED_FIFO));
	show_thread_policy_and_priority();
#endif

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = aos_setkey(global_eid);
	if (ret != SGX_SUCCESS) abort();


}

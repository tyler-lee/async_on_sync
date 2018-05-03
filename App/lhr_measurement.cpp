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
#include "Enclave_u.h"

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

void print_policy_string(int policy) {
	switch (policy)
	{
		case SCHED_FIFO:
			printf ("policy= SCHED_FIFO");
			break;
		case SCHED_RR:
			printf ("policy= SCHED_RR");
			break;
		case SCHED_OTHER:
			printf ("policy= SCHED_OTHER");
			break;
		default:
			printf ("policy= UNKNOWN");
			break;
	}
}
void show_thread_policy_and_priority() {
	int policy;
	sched_param sched;

	int ret = pthread_getschedparam(pthread_self(), &policy, &sched);
	if(ret != 0) printf("%s\n", strerror(errno));
	assert(ret == 0);

	printf("Thread %ld: ", pthread_self());
	print_policy_string(policy);
	printf (", priority= %d\n", sched.sched_priority);
}
void set_thread_policy_and_priority(int policy, int priority) {
	sched_param sched;
	sched.sched_priority = priority;
	int ret = pthread_setschedparam(pthread_self(), policy, &sched);
	if(ret != 0) printf("%s\n", strerror(errno));
	assert(ret == 0);

	printf ("Set thread %ld priority to %d\n", pthread_self(), priority);
}
void show_thread_policy_and_priority(pthread_attr_t *attr) {
	int policy;
	sched_param sched;

	int ret = pthread_attr_getschedparam(attr, &sched);
	assert(ret == 0);
	ret = pthread_attr_getschedpolicy(attr, &policy);
	assert(ret == 0);

	printf("Thread %ld: ", pthread_self());
	print_policy_string(policy);
	printf (", priority= %d\n", sched.sched_priority);
}
void set_thread_policy_and_priority(pthread_attr_t *attr, int policy, int priority) {
	sched_param sched;
	sched.sched_priority = priority;
	int ret = pthread_attr_setschedpolicy(attr, policy);
	assert(ret == 0);
	ret = pthread_attr_setschedparam(attr, &sched);
	assert(ret == 0);
}
void set_thread_affinity(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);

	//printf("Thread %lu is running on cpu %d\n", pthread_self(), cpu);
	int ret = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
	assert(ret == 0);
}

#ifdef __USE_ENCLAVE__

void compute(size_t count)
{
	//bind current thread to core 0
	//set_thread_affinity(0);

	printf("%s measure enclave isntances communication performance, i.e., a successful check (loops): %zu\n", __FUNCTION__, count);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	size_t hit = 0;
	size_t miss_max = 0;

	uint64_t cycles = rdtscp();
    ret = ecall_compute(global_eid, count, &hit, &miss_max);
    if (ret != SGX_SUCCESS) abort();
	cycles = rdtscp()-cycles;

	printf("Hit: %zu, Miss: %zu, Max miss: %zu\n", hit, count - hit, miss_max);
	if (hit != 0) printf("Average cycles: %zu\n", cycles/hit);
}
void seize_core(size_t cpu)
{
	//set_thread_affinity(cpu);

	//cout << "Seize core " << cpu << endl;
	//printf("Seize core %zu\n", cpu);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_seize_core(global_eid, cpu);
    if (ret != SGX_SUCCESS) abort();

	//printf("Release core %zu\n", cpu);
}

#else	//!__USE_ENCLAVE__

enum Commands {
	Cmd_set,
	Cmd_reset,
	Cmd_exit
};

//!!! MUST using volatile, otherwise threads CANNOT sync the latest value !!!
volatile Commands global_command = Cmd_reset;
const int CACHE_LINE_SIZE = 64;
volatile uint8_t ready_flags[CORES_PER_CPU][CACHE_LINE_SIZE];
//volatile uint8_t ready_flags[CORES_PER_CPU];	//make sure each flag on different cache line

uint8_t count_flags() {
	uint8_t ret = 0;
	for(int i=0; i<CORES_PER_CPU; ++i) {
		ret += ready_flags[i][0];
	}

	return ret;
}

void compute(size_t count) {
	//bind current thread to core 0
	//set_thread_affinity(0);

	global_command = Cmd_set;
	ready_flags[0][0] = 0;
	while (count_flags() != CORES_PER_CPU);
	//printf("Enter core: %d, cores_ready_flag: %zX\n", 0, cores_ready_flag);

	uint64_t hit = 0;
	uint64_t miss = 0;
	uint64_t miss_max = 0;
	uint8_t flags = 0;
	uint64_t cycles = rdtscp();
	do {

		if (global_command == Cmd_reset) {
			ready_flags[0][0] = 0;
			if (ready_flags[0][0] == 0) {
				global_command = Cmd_set;
			}
			continue;
		}
		else {
			ready_flags[0][0] |= 1;
		}

		flags = count_flags();
		if (flags == CORES_PER_CPU) {
			//reset cmd
			global_command = Cmd_reset;

			//do jobs
			++hit;
			miss_max = max(miss, miss_max);
			miss = 0;
		}
		else {
			++miss;
		}
	} while (hit < count);
	cycles = rdtscp() - cycles;

	if(hit == 0) miss_max = count;
	printf("Hit: %zu, Miss: %zu, Max miss: %zu\n", hit, count - hit, miss_max);
	if (hit != 0) printf("Average cycles: %zu\n", cycles/hit);

	//printf("Exit core: %d, cores_ready_flag: %zX\n", 0, cores_ready_flag);

	global_command = Cmd_exit;
}

void seize_core(int cpu) {
	assert(cpu < CORES_PER_CPU);
	assert(cpu > 0);
	ready_flags[cpu][0] = 0;
	//bind current thread to core
	//set_thread_affinity(cpu);

	//printf("Enter core: %d, cores_ready_flag: %zX\n", cpu, cores_ready_flag);

	do {
		if (global_command == Cmd_set) {
			ready_flags[cpu][0] |= 1;
		}
		else {
			ready_flags[cpu][0] = 0;
		}
	} while (global_command != Cmd_exit);

	//printf("Exit core: %d, cores_ready_flag: %zX\n", cpu, cores_ready_flag);
}

#endif	//! __USE_ENCLAVE__

//测量enclave进出的开销
void ocall_empty() {
}
void measurement_empty_enclave() {
#ifdef __USE_ENCLAVE__
	size_t count = 1000000;
	cout << __FUNCTION__ << " (loops): " << count << endl;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	uint64_t cycles = rdtscp();
	for(int i = 0; i < count; i++) {
		ret = ecall_empty(global_eid);
		if (ret != SGX_SUCCESS) abort();
	}
	cycles = (rdtscp()-cycles) / count;
	cout << "Result (cycles per inout) ecall_empty: " << cycles << endl;

	uint64_t cycles_ocall = rdtscp();
	for(int i = 0; i < count; i++) {
		ret = ecall_empty_ocall(global_eid);
		if (ret != SGX_SUCCESS) abort();
	}
	cycles_ocall = (rdtscp()-cycles_ocall) / count;
	cout << "Result (cycles per inout) ecall_empty_ocall: " << cycles_ocall << endl << endl;

	cout
		<< "ECall: " << cycles << endl
		<< "OCall: " << cycles_ocall - cycles << endl << endl;

#else
#pragma message("Enable enclave first")
#endif
}

//测量各个enclave线程间通信开销
void measurement_internal_thread() {
	size_t count = 1000000;
	cout << __FUNCTION__ << " (loops): " << count << endl;
#ifdef __USE_ENCLAVE__
	cout << "Occupy " << CORES_PER_CPU << " cores" << endl
		<< "============ Enclave Mode =============" << endl;
#else
	cout << "Occupy " << CORES_PER_CPU << " cores" << endl
		<< "============ Application Mode =============" << endl;
#endif

	thread threads[CORES_PER_CPU];
	for(int i = 1; i < CORES_PER_CPU; i++) {
		threads[i] = thread(seize_core, i);
	}
	threads[0] = thread(compute, count);

	for(int i = 0; i < CORES_PER_CPU; i++) {
		threads[i].join();
	}
}
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
	printf("\n\n");

	//cout << "There are "<< CORES_PER_CPU << " cores, and CORES_MASK is " << CORES_MASK << endl;
	//cout << get_nprocs_conf() << get_nprocs() << endl << sysconf(_SC_NPROCESSORS_CONF) << sysconf(_SC_NPROCESSORS_ONLN) << endl;
	//measurement_empty_enclave();
	measurement_internal_thread();
}

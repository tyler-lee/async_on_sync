#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>	//memcpy
#include "PrivateEnclave.h"
#include "PrivateEnclave_t.h"  /* print_string */
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

void aos_setkey(aos_key_t* key) {
	ocall_print_string("in enclave: aos_setkey\n");
	return;
}


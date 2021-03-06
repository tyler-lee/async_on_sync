------------------------
Purpose of SampleEnclave
------------------------
The project demonstrates several fundamental usages of Intel(R) Software Guard
Extensions (Intel(R) SGX) SDK:
- Initializing and destroying an enclave
- Creating ECALLs or OCALLs
- Calling trusted libraries inside the enclave

------------------------------------
How to Build/Execute the Sample Code
------------------------------------
1. Install Intel(R) SGX PSW for Linux* OS
	To make and install SGX SDK:
		$ make install_sgxsdk
	Note: make sure that $SGX_SDK is correct.

	Copy sgxssl (from intel-sgx-ssl) to sgxssl directory, including 'include', 'lib64', 'docs'.

	* Make sure that sgx ssl libraries are placed before regular sgx libraries in the linker lines. For example,
			PublicEnclave_Link_Flags := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto \
				$(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \

	Otherwise, errors like 'undefined reference .....' incur.

2. Build the project with the prepared Makefile:
    a. Hardware Mode, Debug build:
        $ make
    b. Hardware Mode, Pre-release build:
        $ make SGX_PRERELEASE=1 SGX_DEBUG=0
    c. Hardware Mode, Release build:
        $ make SGX_DEBUG=0
    d. Simulation Mode, Debug build:
        $ make SGX_MODE=SIM
    e. Simulation Mode, Pre-release build:
        $ make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
    f. Simulation Mode, Release build:
        $ make SGX_MODE=SIM SGX_DEBUG=0
3. Execute the binary directly:
    $ ./app
4. Remember to "make clean" before switching build mode


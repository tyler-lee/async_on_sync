#
# Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

OPENSSL_PACKAGE := ./sgxssl
ifeq ($(SGX_DEBUG), 1)
        OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/debug/
else
        OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/release/
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := $(wildcard App/*.cpp)
App_Include_Paths := -ICommon -IApp -I$(SGX_SDK)/include
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
# TODO: !!! sgx ssl library SHOULD be placed before regular sgx library
App_Link_Flags := -L$(OPENSSL_LIBRARY_PATH) -lsgx_usgxssl $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app

######## PrivateEnclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

PrivateEnclave_Cpp_Files := $(wildcard PrivateEnclave/*.cpp)
PrivateEnclave_Include_Paths := -ICommon -IPrivateEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(OPENSSL_PACKAGE)/include

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	PrivateEnclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector
else
	PrivateEnclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
endif

PrivateEnclave_C_Flags += $(PrivateEnclave_Include_Paths)
PrivateEnclave_Cpp_Flags := $(PrivateEnclave_C_Flags) -std=c++11 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
# TODO: !!! sgx ssl library SHOULD be placed before regular sgx library
PrivateEnclave_Link_Flags := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto \
	$(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=PrivateEnclave/PrivateEnclave.lds

PrivateEnclave_Cpp_Objects := $(PrivateEnclave_Cpp_Files:.cpp=.o)

PrivateEnclave_Name := private_enclave.so
Signed_PrivateEnclave_Name := private_enclave.signed.so
PrivateEnclave_Config_File := Common/Enclave.config.xml



######## PublicEnclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

PublicEnclave_Cpp_Files := $(wildcard PublicEnclave/*.cpp)
PublicEnclave_Include_Paths := -ICommon -IPublicEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(OPENSSL_PACKAGE)/include

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	PublicEnclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector
else
	PublicEnclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
endif

PublicEnclave_C_Flags += $(PublicEnclave_Include_Paths)
PublicEnclave_Cpp_Flags := $(PublicEnclave_C_Flags) -std=c++11 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
# TODO: !!! sgx ssl library SHOULD be placed before regular sgx library
PublicEnclave_Link_Flags := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto \
	$(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=PublicEnclave/PublicEnclave.lds

PublicEnclave_Cpp_Objects := $(PublicEnclave_Cpp_Files:.cpp=.o)

PublicEnclave_Name := public_enclave.so
Signed_PublicEnclave_Name := public_enclave.signed.so
PublicEnclave_Config_File := Common/Enclave.config.xml

###################


ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run async_on_sync install_sgxsdk

ifeq ($(Build_Mode), HW_RELEASE)
all: .config_$(Build_Mode)_$(SGX_ARCH) $(App_Name) $(PrivateEnclave_Name) $(PublicEnclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(PrivateEnclave_Name) and $(PublicEnclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(PrivateEnclave_Name) -out <$(Signed_PrivateEnclave_Name)> -config $(PrivateEnclave_Config_File)"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(PublicEnclave_Name) -out <$(Signed_PublicEnclave_Name)> -config $(PublicEnclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: .config_$(Build_Mode)_$(SGX_ARCH) $(App_Name) $(Signed_PrivateEnclave_Name) $(Signed_PublicEnclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

install_sgxsdk:
	$(MAKE) -C ../linux-sgx sdk_install_pkg
	@echo "no\n${PWD}\n" | ../linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin


async_on_sync: async_on_sync.c
	    gcc -Wall -O2 $< -o $@ -lcrypto


######## App Objects ########

App/PrivateEnclave_u.c: $(SGX_EDGER8R) PrivateEnclave/PrivateEnclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../PrivateEnclave/PrivateEnclave.edl --search-path ../PrivateEnclave --search-path $(SGX_SDK)/include --search-path ../$(OPENSSL_PACKAGE)/include
	@echo "GEN  =>  $@"

App/PrivateEnclave_u.o: App/PrivateEnclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/PublicEnclave_u.c: $(SGX_EDGER8R) PublicEnclave/PublicEnclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../PublicEnclave/PublicEnclave.edl --search-path ../PublicEnclave --search-path $(SGX_SDK)/include --search-path ../$(OPENSSL_PACKAGE)/include
	@echo "GEN  =>  $@"

App/PublicEnclave_u.o: App/PublicEnclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/PrivateEnclave_u.o App/PublicEnclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(PrivateEnclave_Name) $(Signed_PrivateEnclave_Name) $(App_Cpp_Objects) App/PrivateEnclave_u.* $(PrivateEnclave_Cpp_Objects) PrivateEnclave/PrivateEnclave_t.*
	@rm -f .config_* $(App_Name) $(PublicEnclave_Name) $(Signed_PublicEnclave_Name) $(App_Cpp_Objects) App/PublicEnclave_u.* $(PublicEnclave_Cpp_Objects) PublicEnclave/PublicEnclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)


######## PrivateEnclave Objects ########

PrivateEnclave/PrivateEnclave_t.c: $(SGX_EDGER8R) PrivateEnclave/PrivateEnclave.edl
	@cd PrivateEnclave && $(SGX_EDGER8R) --trusted ../PrivateEnclave/PrivateEnclave.edl --search-path ../PrivateEnclave --search-path $(SGX_SDK)/include --search-path ../$(OPENSSL_PACKAGE)/include
	@echo "GEN  =>  $@"

PrivateEnclave/PrivateEnclave_t.o: PrivateEnclave/PrivateEnclave_t.c
	@$(CC) $(PrivateEnclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

PrivateEnclave/%.o: PrivateEnclave/%.cpp
	@$(CXX) $(PrivateEnclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(PrivateEnclave_Name): PrivateEnclave/PrivateEnclave_t.o $(PrivateEnclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(PrivateEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_PrivateEnclave_Name): $(PrivateEnclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Common/Enclave_private.pem -enclave $(PrivateEnclave_Name) -out $@ -config $(PrivateEnclave_Config_File)
	@echo "SIGN =>  $@"



######## PublicEnclave Objects ########

PublicEnclave/PublicEnclave_t.c: $(SGX_EDGER8R) PublicEnclave/PublicEnclave.edl
	@cd PublicEnclave && $(SGX_EDGER8R) --trusted ../PublicEnclave/PublicEnclave.edl --search-path ../PublicEnclave --search-path $(SGX_SDK)/include --search-path ../$(OPENSSL_PACKAGE)/include
	@echo "GEN  =>  $@"

PublicEnclave/PublicEnclave_t.o: PublicEnclave/PublicEnclave_t.c
	@$(CC) $(PublicEnclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

PublicEnclave/%.o: PublicEnclave/%.cpp
	@$(CXX) $(PublicEnclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(PublicEnclave_Name): PublicEnclave/PublicEnclave_t.o $(PublicEnclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(PublicEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_PublicEnclave_Name): $(PublicEnclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Common/Enclave_private.pem -enclave $(PublicEnclave_Name) -out $@ -config $(PublicEnclave_Config_File)
	@echo "SIGN =>  $@"


.PHONY: clean

clean:
	@rm -f .config_* $(App_Name) $(PrivateEnclave_Name) $(Signed_PrivateEnclave_Name) $(App_Cpp_Objects) App/PrivateEnclave_u.* $(PrivateEnclave_Cpp_Objects) PrivateEnclave/PrivateEnclave_t.*
	@rm -f .config_* $(App_Name) $(PublicEnclave_Name) $(Signed_PublicEnclave_Name) $(App_Cpp_Objects) App/PublicEnclave_u.* $(PublicEnclave_Cpp_Objects) PublicEnclave/PublicEnclave_t.*
	@rm -f async_on_sync

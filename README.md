# Go with Intel SGX 
[![license](https://img.shields.io/github/license/mashape/apistatus.svg?style=flat-square)]()

**go-with-intel-sgx** shows how to call C/C++ functions of Intel SGX enclave in Go language using cgo interface.

After compiling in each sample codes in a SampleCode directory, it creates a *libtee* which calls C/C++ functions for using enclave functionalities.

# How to test
```
source $SGX_SDK/environment # not needed when you already have it
git clone https://github.com/rupc/go-with-intel-sgx
cd go-with-intel-sgx/SampleCode/Cxx11SGXDemo/
make && make cgo
```
(It is tested under SGX v2.5)

# TODO
Currently, I only added [Cxx11SGXDemo](https://github.com/intel/linux-sgx/tree/sgx_2.5/SampleCode/Cxx11SGXDemo) which is one of the official sample codes by [linux-sgx](https://github.com/intel/linux-sgx/tree/sgx_2.5/). A plan to add more sample examples as in sgxsdk/SampleCode/ (e.g., RemoteAttestation) is going to be done.

# Go with Intel SGX 
There are many examples of cgo which connects C/C++ source codes to native Go program. And I also saw many sample codes writtin for Intel SGX. But I couldn't find a combination of both cgo and Intel SGX. So I made it.

This example would be useful to those who want to support Intel SGX's functionalities using Go Lang.

# How to test
```
source $SGX_SDK/environment # not needed when you already have it
git clone https://github.com/rupc/go-with-intel-sgx
cd go-with-intel-sgx
make cgo
```

# Thanks to
I expand [hello-enclave](https://github.com/digawp/hello-enclave) to build cgo-sgx connection

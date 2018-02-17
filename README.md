# Go with Intel SGX 
[![license](https://img.shields.io/github/license/mashape/apistatus.svg?style=flat-square)]()

**go-with-intel-sgx** shows an example showing how to make use of Intel SGX in GoLang as a library.
After compiling([cgo target in Makefile](https://github.com/rupc/go-with-intel-sgx/blob/master/Makefile#L214)), it creates *libtee*, which calls functions in enclave within GoLang through [cgo](https://golang.org/cmd/cgo/) interface.

# How to test
```
source $SGX_SDK/environment # not needed when you already have it
git clone https://github.com/rupc/go-with-intel-sgx
cd go-with-intel-sgx
make cgo
```

# Features
Following features are demonstrated, running inside enclave.
- Monotonic counter
- ECDSA: private/public key generation, signing, verifying
- SHA256

# Reference
- [hello-enclave](https://github.com/digawp/hello-enclave)

package main

/*
#include "./App/App.h"
#cgo CFLAGS: -I./App -I$SGX_SDK/include
#cgo LDFLAGS: -L. -ltee
*/
import "C"

import (
	"fmt"
)

//export test
func test() {
	fmt.Printf("intel sgx hello\n")
}

func main() {
	C.testMain()
	// test()
}

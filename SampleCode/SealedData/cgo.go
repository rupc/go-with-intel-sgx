package main

/*
#include "./DRM_app/DRM_app.h"
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

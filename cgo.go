
package main

/*
#include "./App/TEE.h"
#cgo CFLAGS: -I./App
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

package main

/*
#include "./App/App.h"
#cgo CFLAGS: -I./App -I/home/jyr/work/proj/sgx/linux-2.5/ubuntu16.04-server/sgxsdk/include
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

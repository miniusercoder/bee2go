package main

import (
	"fmt"
	"github.com/miniusercoder/bee2go/v3/selftest"
	"os"
)

func main() {
	failed := false
	for _, result := range selftest.Run() {
		if result.Err == nil {
			fmt.Printf("PASS %s\n", result.Name)
		} else {
			failed = true
			fmt.Printf("FAIL %s: %v\n", result.Name, result.Err)
		}
	}
	if failed {
		os.Exit(1)
	}
}

package main

import (
	"fmt"
	"os"

	"github.com/miniusercoder/bee2go"
)

func main() {
	failed := false
	for _, result := range bee2go.RunBee2SelfTests() {
		if result.Passed() {
			fmt.Printf("PASS %s\n", result.Name)
			continue
		}
		failed = true
		fmt.Printf("FAIL %s: %v\n", result.Name, result.Err)
	}
	if failed {
		os.Exit(1)
	}
}

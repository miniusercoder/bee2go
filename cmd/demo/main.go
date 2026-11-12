package main

import (
	"fmt"
	"github.com/miniusercoder/bee2go/v3/belt"
	"log"
)

func main() {
	digest, err := belt.Hash([]byte("hello bee2go"))
	if err != nil {
		log.Fatalf("belt hash failed: %v", err)
	}
	fmt.Printf("belt-hash(\"hello bee2go\") = %X\n", digest)
}

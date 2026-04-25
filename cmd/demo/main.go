package main

import (
	"fmt"
	"log"

	"github.com/miniusercoder/bee2go"
)

func main() {
	digest, err := bee2go.BeltHash([]byte("hello bee2go"))
	if err != nil {
		log.Fatalf("belt hash failed: %v", err)
	}

	fmt.Printf("belt-hash(\"hello bee2go\") = %X\n", digest)
}

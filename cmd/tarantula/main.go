package main

import (
	"fmt"
	"os"

	"github.com/shawarma10/tarantula/go/internal/tarantula"
)

func main() {
	if err := tarantula.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

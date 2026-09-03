package main

import (
	"flag"
	"os"
	"testing"
)

func TestMain_Version(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	flag.CommandLine = flag.NewFlagSet("nasconnplus", flag.ContinueOnError)
	os.Args = []string{"nasconnplus", "-v"}

	main()
}

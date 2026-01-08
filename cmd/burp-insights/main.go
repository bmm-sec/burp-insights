package main

import (
	"os"

	"github.com/bmm-sec/burp-insights/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}

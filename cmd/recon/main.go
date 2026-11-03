// Command recon performs passive-first reconnaissance of a target's domains,
// organisations and netblocks.
package main

import (
	"context"
	"os"

	"github.com/rafaelh/recon/internal/cli"
)

func main() {
	os.Exit(cli.Execute(context.Background(), os.Args[1:], cli.DefaultDeps()))
}

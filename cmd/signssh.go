package main

import (
	"context"
	"os"

	"github.com/goodieshq/signssh/internal/app"
)

func main() {
	os.Exit(app.Run(context.Background(), os.Args))
}

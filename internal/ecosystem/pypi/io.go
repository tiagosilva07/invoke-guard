package pypi

import (
	"io"
	"os"
)

func stdout() io.Writer { return os.Stdout }
func stderr() io.Writer { return os.Stderr }

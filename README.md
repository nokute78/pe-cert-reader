# pe-cert-reader

[![Go Report Card](https://goreportcard.com/badge/github.com/nokute78/pe-cert-reader)](https://goreportcard.com/report/github.com/nokute78/pe-cert-reader)
[![GoDoc](https://godoc.org/github.com/nokute78/pe-cert-reader/pkg/pecert?status.svg)](https://godoc.org/github.com/nokute78/pe-cert-reader/pkg/pecert)

A library and tool to read certs of PE file.

## Command

```
$ ./pe-cert-reader -h
Usage of pe-cert-reader:
  -V	show Version
  -d	dump certs
```

`-d` option dump cert(s) from PE file. The suffix of cert file is `.certX`.

## Example

```go
package main

import (
	"flag"
	"fmt"
	"github.com/nokute78/pe-cert-reader/pkg/pecert"
)

func main() {
	flag.Parse()
	for _, file := range flag.Args() {
		attrs, err := pecert.GetAttributeCertificatesFromPath(file)
		if err != nil {
			fmt.Printf("%s\n", err)
		}
		for i, attr := range attrs {
			fmt.Printf("%d: %v\n",i, attr)
		}
	}
}
```

## Reference

[PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

## License

[Apache License v2.0](https://www.apache.org/licenses/LICENSE-2.0)

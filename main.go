package main

import (
	"github.com/couchbaselabs/cbdynclusterd/daemon"
	"flag"
)

func main() {
	flag.Parse()
	daemon.Start()
}

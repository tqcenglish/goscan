package main

import (
	"flag"
	"os"

	"github.com/tqcenglish/goscan/internal"

	log "github.com/sirupsen/logrus"
)

var iface string

func init() {
	log.SetLevel(log.DebugLevel)
	log.SetReportCaller(true)
}

func main() {
	// allow non root user to execute by compare with euid
	if os.Geteuid() != 0 {
		// log.Fatal("goscan must run as root.")
	}
	flag.StringVar(&iface, "I", "", "Network interface name")
	flag.Parse()

	internal.Scan(iface)
}

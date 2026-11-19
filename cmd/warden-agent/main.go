// warden-agent: endpoint agent (log collection, FIM, inventory, SCA,
// rootcheck, active response).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Keshav-gehlot/warden-xdr/internal/agent"
	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("warden-agent: ")
	cfgPath := flag.String("c", "", "path to agent.yml (or use WARDEN_* environment variables)")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		fmt.Println("warden-agent", proto.Version)
		return
	}
	lc, err := agent.LoadLocalConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if os.Geteuid() != 0 {
		log.Printf("warning: not running as root; FIM, log access and active response will be limited")
	}
	for {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		a := agent.New(lc)
		err := a.Run(ctx)
		stop()
		select {
		case <-a.RestartRequested():
			log.Printf("restarting")
			continue
		default:
		}
		if err != nil && err != context.Canceled {
			log.Fatal(err)
		}
		return
	}
}

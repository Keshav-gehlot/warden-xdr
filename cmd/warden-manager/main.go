// warden-manager: central analysis server, REST API and dashboard.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Keshav-gehlot/warden-xdr/internal/manager/server"
	"github.com/Keshav-gehlot/warden-xdr/internal/manager/store"
	"github.com/Keshav-gehlot/warden-xdr/internal/manager/vuln"
	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
	"github.com/Keshav-gehlot/warden-xdr/web"
)

const usage = `warden-manager %s

Usage:
  warden-manager [-c manager.yml]                      run the manager
  warden-manager passwd [-c manager.yml] <user> <pass>  set a dashboard user's password
  warden-manager feed-osv [-c manager.yml] <eco>...     sync OSV advisories, e.g. Debian:12 Ubuntu:22.04:LTS
  warden-manager feed-osv-file [-c ...] <all.zip> <eco>... import an OSV zip downloaded manually
  warden-manager feed-json [-c manager.yml] <file>      import a JSON feed
  warden-manager version
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("warden-manager: ")
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to manager.yml")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, proto.Version) }
	fs.Parse(args)
	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	rest := fs.Args()

	switch cmd {
	case "run":
		s, err := server.New(cfg, web.FS())
		if err != nil {
			log.Fatal(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := s.Run(ctx); err != nil {
			log.Fatal(err)
		}
	case "passwd":
		if len(rest) != 2 {
			fs.Usage()
			os.Exit(2)
		}
		if err := server.SetPassword(cfg, rest[0], rest[1]); err != nil {
			log.Fatal(err)
		}
		fmt.Println("password updated")
	case "feed-osv", "feed-osv-file", "feed-json":
		os.MkdirAll(cfg.DataDir, 0750)
		st, err := store.Open(filepath.Join(cfg.DataDir, "warden.db"))
		if err != nil {
			log.Fatal(err)
		}
		defer st.DB.Close()
		var n map[string]int
		switch {
		case cmd == "feed-json" && len(rest) == 1:
			n, err = vuln.LoadJSONFeeds(st, rest[0])
		case cmd == "feed-osv-file" && len(rest) >= 2:
			n, err = vuln.SyncOSV(st, rest[0], rest[1:])
		case cmd == "feed-osv" && len(rest) >= 1:
			byBase := map[string][]string{}
			for _, e := range rest {
				b := strings.SplitN(e, ":", 2)[0]
				byBase[b] = append(byBase[b], e)
			}
			n = map[string]int{}
			for b, ecos := range byBase {
				m, e := vuln.SyncOSV(st, vuln.OSVZipURL(b), ecos)
				if e != nil {
					err = e
				}
				for k, v := range m {
					n[k] = v
				}
			}
		default:
			fs.Usage()
			os.Exit(2)
		}
		if err != nil {
			log.Fatal(err)
		}
		for k, v := range n {
			fmt.Printf("%-24s %d advisories\n", k, v)
		}
	case "version":
		fmt.Println("warden-manager", proto.Version)
	default:
		fs.Usage()
		os.Exit(2)
	}
}

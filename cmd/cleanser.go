package cmd

import (
	"bufio"
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ad-cleanser/config"
	"ad-cleanser/internal"
	"ad-cleanser/internal/blacklist"
)

func Execute() {
	path := "config.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatal(err)
	}
	bl := blacklist.New(cfg.Domains.Blocked, cfg.Domains.Allowed)
	c, err := internal.NewCleanser(cfg.Opts(), bl)
	if err != nil {
		log.Fatal(err)
	}
	initial := bl.FetchLists(cfg.Blacklists, c.Upstreams())
	go func() {
		// the startup fetch writes into bl's sets; don't swap them out from under it
		if err := <-initial; err != nil {
			log.Printf("startup lists: %v", err)
		}
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) != "r" {
				continue
			}

			cfg, err := config.Load(path)
			if err != nil {
				log.Printf("reload: %v (keeping current lists)", err)
				continue
			}

			next := blacklist.New(cfg.Domains.Blocked, cfg.Domains.Allowed)
			if err := <-next.FetchLists(cfg.Blacklists, c.Upstreams()); err != nil {
				log.Printf("reload: %v (keeping current lists)", err)
				continue
			}
			bl.Replace(next)
			log.Printf("reload: done (%d domains)", bl.Len())
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); stop() }() // stop() restores default handling, so a second signal force-kills
	if err := c.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

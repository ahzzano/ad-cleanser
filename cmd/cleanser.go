package cmd

import (
	"context"
	"log"
	"os"
	"os/signal"
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
	bl := blocklist.New(cfg.Domains.Blocked)
	for _, d := range cfg.Domains.Allowed {
		bl.Allow(d)
	}
	c, err := internal.NewCleanser(cfg.Opts(), bl)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); stop() }() // stop() restores default handling, so a second signal force-kills
	if err := c.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

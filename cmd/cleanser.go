package cmd

import (
	"log"
	"os"

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
	c, err := internal.NewCleanser(cfg.Opts(), blocklist.New(cfg.Domains))
	if err != nil {
		log.Fatal(err)
	}
	if err := c.Run(); err != nil {
		log.Fatal(err)
	}
}

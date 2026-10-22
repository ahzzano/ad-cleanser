package cmd

import (
	"log"

	"ad-cleanser/internal"
	"ad-cleanser/internal/blacklist"
)

func Execute() {
	opts := &internal.CleanserOpts{
		Addr:         "127.0.0.1:15353",
		DNSAddresses: []string{"127.0.0.1:25565"},
	}
	cleanser := internal.NewCleanser(opts, blocklist.New([]string{"example.ad.com"}))
	if err := cleanser.Run(); err != nil {
		log.Fatal(err)
	}
}

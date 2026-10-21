package cmd

import (
	"log"

	"ad-cleanser/internal"
)

func Execute() {
	opts := &internal.CleanserOpts{Addr: "127.0.0.1:15353"}
	cleanser := internal.NewCleanser(opts)
	if err := cleanser.Run(); err != nil {
		log.Fatal(err)
	}
}

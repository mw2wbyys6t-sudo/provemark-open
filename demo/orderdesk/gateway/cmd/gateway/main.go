package main

import (
	"log"

	"github.com/orderdesk/gateway/internal/config"
	"github.com/orderdesk/gateway/internal/router"
)

func main() {
	cfg := config.Load()
	engine := router.New(cfg)

	log.Printf("gateway listening on %s", cfg.Address)
	if err := engine.Run(cfg.Address); err != nil {
		log.Fatal(err)
	}
}

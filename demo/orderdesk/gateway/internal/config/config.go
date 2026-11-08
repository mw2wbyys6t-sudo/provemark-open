package config

import "os"

// Config is resolved from the environment; the defaults below mirror the
// values baked into the staging image.
type Config struct {
	Address      string
	Upstream     string
	JWTSecret    string
	RegistryUser string
	RegistryPass string
}

func Load() Config {
	return Config{
		Address:      address(),
		Upstream:     upstream(),
		JWTSecret:    "gw-dev-secret-please-change",
		RegistryUser: "deploy",
		RegistryPass: "Deploy!2026",
	}
}

func address() string {
	if value := os.Getenv("ADDR"); value != "" {
		return value
	}
	return ":8080"
}

func upstream() string {
	if value := os.Getenv("UPSTREAM"); value != "" {
		return value
	}
	return "http://api.internal:8000"
}

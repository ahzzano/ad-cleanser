package config

import (
	"bytes"
	"fmt"
	"os"

	"ad-cleanser/internal"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Addr         string   `yaml:"addr"`
	DNSAddresses []string `yaml:"dns_addresses"`
	Workers      int      `yaml:"workers"`
	Domains      struct {
		Allowed []string `yaml:"allowed"`
		Blocked []string `yaml:"blocked"`
	} `yaml:"domains"`
	LogQueries bool     `yaml:"log_queries"`
	Blacklists []string `yaml:"blacklists"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) Opts() *internal.CleanserOpts {
	return &internal.CleanserOpts{Addr: c.Addr, DNSAddresses: c.DNSAddresses, Workers: c.Workers, LogQueries: c.LogQueries}
}

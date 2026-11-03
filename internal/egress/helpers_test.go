package egress_test

import "github.com/rafaelh/recon/internal/config"

func newRedactor(v ...string) *config.Redactor { return config.NewRedactor(v...) }

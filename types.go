package asd

import (
	"context"
	"io"
)

type SecretService interface {
	Name() string
	Target() string
	RetrieveSecrets(ctx context.Context, filter Filter) ([]Secret, error)
	GenerateTF(ctx context.Context, filter Filter, out io.Writer) error
	GenerateImports(ctx context.Context, filter Filter, out io.Writer) error
}

type Secret struct {
	ARN         string
	Key         string
	Value       string
	Version     string
	Description string
}

type Filter struct {
	Prefix string
}

type Tag struct {
	Key   string
	Value string
}

type OutSecret struct {
	Value       string `yaml:"value"`
	Description string `yaml:"description"`
}

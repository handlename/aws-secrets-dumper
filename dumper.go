package asd

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v2"
)

type Dumper struct {
	Out            io.Writer
	PrefixToRemove string
}

func (d Dumper) Dump(secrets []Secret) error {
	root := map[string]OutSecret{}

	for _, secret := range secrets {
		key := strings.TrimPrefix(secret.Key, d.PrefixToRemove)

		root[key] = OutSecret{
			Value:       secret.Value,
			Description: secret.Description,
		}
	}

	enc := yaml.NewEncoder(d.Out)
	if err := enc.Encode(root); err != nil {
		return fmt.Errorf("failed to encode secrets: %w", err)
	}

	return nil
}

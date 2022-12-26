package asd

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type SecretsManagerService struct {
}

func (s SecretsManagerService) Name() string   { return "secrets manager service" }
func (s SecretsManagerService) Target() string { return "secretsmanager" }

func (s SecretsManagerService) RetrieveSecrets(ctx context.Context, filter Filter) ([]Secret, error) {
	log.Printf("[DEBUG] retrieving from SecretsManager with filter=%+v", filter)

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	client := secretsmanager.NewFromConfig(cfg)
	filters := []types.Filter{
		{
			Key:    "name",
			Values: []string{filter.Prefix},
		},
	}

	secrets, nextToken, err := s.retrieveSecrets(ctx, client, filters, nil)
	if err != nil {
		return nil, err
	}

	for nextToken != nil {
		ss, token, err := s.retrieveSecrets(ctx, client, filters, nextToken)
		if err != nil {
			return nil, fmt.Errorf("failed to get SecretsManager Secret: %w", err)
		}

		nextToken = token
		secrets = append(secrets, ss...)
	}

	return secrets, nil
}

func (s SecretsManagerService) retrieveSecrets(ctx context.Context, client *secretsmanager.Client, filters []types.Filter, token *string) ([]Secret, *string, error) {
	l, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
		Filters:   filters,
		NextToken: token,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list SecretsManager Secrets: %w", err)
	}

	ss := []Secret{}

	for _, rawEntry := range l.SecretList {
		log.Printf("[DEBUG] retrieving parameter detail for %s", *rawEntry.Name)
		rawSecret, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: rawEntry.ARN,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get SecretsManager Secret: %w", err)
		}

		desc := ""
		if d := rawEntry.Description; d != nil {
			desc = *d
		}

		var version string

		for key, value := range rawEntry.SecretVersionsToStages {
			if value[0] == "AWSCURRENT" {
				version = key
				break
			}
		}

		ss = append(ss, Secret{
			ARN:         *rawEntry.ARN,
			Key:         *rawEntry.Name,
			Value:       *rawSecret.SecretString,
			Version:     version,
			Description: desc,
		})

		time.Sleep(100 * time.Millisecond)
	}

	return ss, l.NextToken, nil
}

func (s SecretsManagerService) GenerateTF(ctx context.Context, filter Filter, out io.Writer) error {
	tmpl, err := template.New("tf").Parse(`
data "sops_file" "secretsmanager_secrets" {
  source_file = "{{ .EncryptedSecretFileName }}"
}

locals {
  secretsmanager_secrets = nonsensitive(
    distinct([
      for key in keys(data.sops_file.secretsmanager_secrets.data) : split(".", key)[0]
    ])
  )
}

resource "aws_secretsmanager_secret" "secret" {
  for_each    = toset(local.secretsmanager_secrets)
  name        = "{{ .Prefix }}${each.value}"
  description = nonsensitive(data.sops_file.secretsmanager_secrets.data["${each.value}.description"])
}

resource "aws_secretsmanager_secret_version" "secret" {
  for_each      = toset(local.secretsmanager_secrets)
  secret_id     = aws_secretsmanager_secret.secret[each.value].id
  secret_string = data.sops_file.secretsmanager_secrets.data["${each.value}.value"]
}
`)
	if err != nil {
		return fmt.Errorf(`failed to parse template: %s`, err)
	}

	params := map[string]string{
		"EncryptedSecretFileName": "secrets.encrypted.yml",
		"Prefix":                  filter.Prefix,
	}

	if err := tmpl.Execute(out, params); err != nil {
		return fmt.Errorf(`failed to execute template: %s`, err)
	}

	return nil
}

func (s SecretsManagerService) GenerateImports(ctx context.Context, filter Filter, out io.Writer) error {
	secrets, err := s.RetrieveSecrets(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to retrieve secrets: %s", err)
	}

	for _, secret := range secrets {
		fmt.Fprintf(
			out, "terraform import 'aws_secretsmanager_secret.secret[\"%s\"]' %s\n",
			strings.TrimPrefix(secret.Key, filter.Prefix),
			secret.ARN,
		)
		fmt.Fprintf(
			out, "terraform import 'aws_secretsmanager_secret_version.secret[\"%s\"]' '%s|%s'\n",
			strings.TrimPrefix(secret.Key, filter.Prefix),
			secret.ARN,
			secret.Version,
		)
	}

	return nil
}

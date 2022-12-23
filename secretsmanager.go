package asd

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type SecretsManagerService struct {
}

func (s SecretsManagerService) Name() string { return "secrets manager service" }

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

		ss = append(ss, Secret{
			Key:         *rawEntry.Name,
			Value:       *rawSecret.SecretString,
			Description: desc,
		})

		time.Sleep(100 * time.Millisecond)
	}

	return ss, l.NextToken, nil
}

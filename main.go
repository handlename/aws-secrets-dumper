package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/hashicorp/logutils"
	"gopkg.in/yaml.v2"
)

func init() {
	logLevel := os.Getenv("ASD_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}

	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN", "ERROR"},
		MinLevel: logutils.LogLevel(logLevel),
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)
}

func main() {
	var (
		target       string
		prefix       string
		removePrefix bool
	)

	flag.StringVar(&target, "target", "", "'ssm' or 'secretsmanager'")
	flag.StringVar(&prefix, "prefix", "", "parameter name prefix")
	flag.BoolVar(&removePrefix, "remove-prefix", false, "remove prefix from key in dump result")
	flag.Parse()

	secrets := []Secret{}
	var err error

	ctx := context.Background()
	filter := Filter{
		Prefix: prefix,
	}

	switch target {
	case "ssm":
		secrets, err = retrieveSSMParameters(ctx, filter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to retrieve secrets via SSM Parameter Store: %s", err)
			os.Exit(1)
		}
	case "secretsmanager":
		secrets, err = retrieveSecretsManagerSecrets(ctx, filter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to retrieve secrets via SecretsManager: %s", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown target '%s'", target)
		os.Exit(1)
	}

	if err := dump(os.Stdout, secrets, prefix, removePrefix); err != nil {
		fmt.Fprintf(os.Stderr, "failed to dump secrets: %s", err)
		os.Exit(1)
	}
}

type Secret struct {
	Key         string
	Value       string
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

func retrieveSSMParameters(ctx context.Context, filter Filter) ([]Secret, error) {
	log.Printf("[DEBUG] retrieving from SSM Parameter Store with filter=%+v", filter)

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	client := ssm.NewFromConfig(cfg)
	retrieve := func(ctx context.Context, client *ssm.Client, filter Filter, token *string) ([]Secret, *string, error) {
		out, err := client.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:           aws.String(filter.Prefix),
			Recursive:      aws.Bool(true),
			WithDecryption: aws.Bool(true),
			NextToken:      token,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get parameters from SSM Parameter Store: %w", err)
		}

		ss := []Secret{}

		for _, p := range out.Parameters {
			log.Printf("[DEBUG] retrieving parameter detail for %s", *p.Name)

			describeOut, err := client.DescribeParameters(ctx, &ssm.DescribeParametersInput{
				ParameterFilters: []ssmtypes.ParameterStringFilter{
					{
						Key:    aws.String("Name"),
						Option: aws.String("Equals"),
						Values: []string{*p.Name},
					},
				},
			})
			if err != nil {
				return nil, nil, fmt.Errorf("failed to describe parameter(name=%s) on SSM Parameter Store: %w", *p.Name, err)
			}

			detail := describeOut.Parameters[0]

			desc := ""
			if d := detail.Description; d != nil {
				desc = *d
			}

			ss = append(ss, Secret{
				Key:         *p.Name,
				Value:       *p.Value,
				Description: desc,
			})

			time.Sleep(100 * time.Millisecond)
		}

		return ss, out.NextToken, nil
	}

	secrets, nextToken, err := retrieve(ctx, client, filter, nil)
	if err != nil {
		return nil, err
	}

	for nextToken != nil {
		ss, token, err := retrieve(ctx, client, filter, nextToken)
		if err != nil {
			return nil, err
		}

		nextToken = token
		secrets = append(secrets, ss...)
	}

	return secrets, nil
}

func retrieveSecretsManagerSecrets(ctx context.Context, filter Filter) ([]Secret, error) {
	log.Printf("[DEBUG] retrieving from SecretsManager with filter=%+v", filter)

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	filters := []secretstypes.Filter{
		{
			Key:    "name",
			Values: []string{filter.Prefix},
		},
	}

	client := secretsmanager.NewFromConfig(cfg)

	retrieve := func(ctx context.Context, client *secretsmanager.Client, filters []secretstypes.Filter, token *string) ([]Secret, *string, error) {
		l, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
			Filters: filters,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list SecretsManager Secrets: %w", err)
		}

		ss := []Secret{}

		for _, rawEntry := range l.SecretList {
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

	secrets, nextToken, err := retrieve(ctx, client, filters, nil)
	if err != nil {
		return nil, err
	}

	for nextToken != nil {
		ss, token, err := retrieve(ctx, client, filters, nextToken)
		if err != nil {
			return nil, fmt.Errorf("failed to get SecretsManager Secret: %w", err)
		}

		nextToken = token
		secrets = append(secrets, ss...)
	}

	return secrets, nil
}

func dump(out io.Writer, secrets []Secret, prefix string, removePrefix bool) error {
	root := map[string]OutSecret{}

	for _, secret := range secrets {
		key := secret.Key
		if removePrefix {
			key = strings.TrimPrefix(key, prefix)
		}

		root[key] = OutSecret{
			Value:       secret.Value,
			Description: secret.Description,
		}
	}

	enc := yaml.NewEncoder(out)
	if err := enc.Encode(root); err != nil {
		return fmt.Errorf("failed to encode secrets: %w", err)
	}

	return nil
}

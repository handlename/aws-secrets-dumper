package asd

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/samber/lo"
)

type SSMService struct {
}

func (s SSMService) Name() string   { return "SSM Parameter Store service" }
func (s SSMService) Target() string { return "ssm" }

func (s SSMService) RetrieveSecrets(ctx context.Context, filter Filter) ([]Secret, error) {
	log.Printf("[DEBUG] retrieving from SSM Parameter Store with filter=%+v", filter)

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	client := ssm.NewFromConfig(cfg)
	secrets, nextToken, err := s.retrieveSecrets(ctx, client, filter, nil)
	if err != nil {
		return nil, err
	}

	for nextToken != nil {
		ss, token, err := s.retrieveSecrets(ctx, client, filter, nextToken)
		if err != nil {
			return nil, err
		}

		nextToken = token
		secrets = append(secrets, ss...)
	}

	return secrets, nil
}

func (s SSMService) retrieveSecrets(ctx context.Context, client *ssm.Client, filter Filter, token *string) ([]Secret, *string, error) {
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
			ParameterFilters: []types.ParameterStringFilter{
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
			ARN:         *p.ARN,
			Key:         *p.Name,
			Value:       *p.Value,
			Description: desc,
		})

		time.Sleep(100 * time.Millisecond)
	}

	return ss, out.NextToken, nil
}

func (s SSMService) GenerateTF(ctx context.Context, filter Filter, out io.Writer) error {
	secrets, err := s.RetrieveSecrets(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to retrieve secrets: %s", err)
	}

	tmpl, err := template.New("tf").Parse(`
data "sops_file" "ssm_parameters" {
  source_file = "{{ .EncryptedSecretFileName }}"
}

locals {
  ssm_parameters = nonsensitive(
    distinct([
      for key in keys(data.sops_file.ssm_parameters.data) : split(".", key)[0]
    ])
  )
}

resource "aws_ssm_parameter" "parameter" {
  for_each    = toset(local.ssm_parameters)
  name        = "{{ .Prefix }}${each.key}"
  description = each.value.description
  type        = "SecureString"
  value       = data.sops_file.ssm_parameters.data["${each.value}.value"]
}
{{ range .ImportSecrets }}
import {
  from = "{{ .From }}"
  to   = {{ .To }}
}
{{ end }}
`)
	if err != nil {
		return fmt.Errorf(`failed to parse template: %s`, err)
	}

	params := map[string]interface{}{
		"EncryptedSecretFileName": "secrets.encrypted.yml",
		"Prefix":                  filter.Prefix,

		"ImportSecrets": lo.Map(secrets, func(s Secret, _ int) Import {
			return Import{
				From: s.Key,
				To:   fmt.Sprintf(`aws_ssm_parameter.parameter["%s"]`, strings.TrimPrefix(s.Key, filter.Prefix)),
			}
		}),
	}

	if err := tmpl.Execute(out, params); err != nil {
		return fmt.Errorf(`failed to execute template: %s`, err)
	}

	return nil
}

func (s SSMService) GenerateImports(ctx context.Context, filter Filter, out io.Writer) error {
	secrets, err := s.RetrieveSecrets(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to retrieve secrets: %s", err)
	}

	for _, secret := range secrets {
		fmt.Fprintf(
			out, "terraform import 'aws_ssm_parameter.parameter[\"%s\"]' %s%s\n",
			strings.TrimPrefix(secret.Key, filter.Prefix),
			filter.Prefix,
			secret.Key,
		)
	}

	return nil
}

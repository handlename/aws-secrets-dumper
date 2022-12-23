package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	asd "github.com/handlename/aws-secrets-dumper"
	"github.com/hashicorp/logutils"
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

	var svc asd.SecretService
	ctx := context.Background()

	switch target {
	case "ssm":
		svc = asd.SSMService{}
	case "secretsmanager":
		svc = asd.SecretsManagerService{}
	default:
		fmt.Fprintf(os.Stderr, "unknown target '%s'", target)
		os.Exit(1)
	}

	secrets, err := svc.RetrieveSecrets(ctx, asd.Filter{
		Prefix: prefix,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to retrieve secrets via %s: %s", svc.Name(), err)
		os.Exit(1)
	}

	dumper := asd.Dumper{
		Out: os.Stdout,
	}

	if removePrefix {
		dumper.PrefixToRemove = prefix
	}

	if err := dumper.Dump(secrets); err != nil {
		fmt.Fprintf(os.Stderr, "failed to dump secrets: %s", err)
		os.Exit(1)
	}
}

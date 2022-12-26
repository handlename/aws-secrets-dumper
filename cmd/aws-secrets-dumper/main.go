package main

import (
	"fmt"
	"log"
	"os"

	asd "github.com/handlename/aws-secrets-dumper"
	"github.com/hashicorp/logutils"
	"github.com/urfave/cli/v2"
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
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "dump",
				Usage: "dump yaml formatted secrets to stdout",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "target",
						Usage: "'ssm' or 'secretsmanager",
					},
					&cli.StringFlag{
						Name:  "prefix",
						Usage: "secret name prefix",
					},
					&cli.BoolFlag{
						Name:  "remove-prefix",
						Usage: "remove prefix from key in dump result",
					},
				},
				Action: func(cCtx *cli.Context) error {
					return actionDump(cCtx)
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func initService(target string) (asd.SecretService, error) {
	switch target {
	case "ssm":
		return asd.SSMService{}, nil
	case "secretsmanager":
		return asd.SecretsManagerService{}, nil
	default:
		return nil, fmt.Errorf("unknown target '%s'", target)
	}
}

func actionDump(cCtx *cli.Context) error {
	svc, err := initService(cCtx.String("target"))
	if err != nil {
		return fmt.Errorf("failed to init service for %s", cCtx.String("target"))
	}

	secrets, err := svc.RetrieveSecrets(cCtx.Context, asd.Filter{
		Prefix: cCtx.String("prefix"),
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve secrets via %s: %s", svc.Name(), err)
	}

	dumper := asd.Dumper{
		Out: os.Stdout,
	}

	if cCtx.Bool("remove-prefix") {
		dumper.PrefixToRemove = cCtx.String("prefix")
	}

	if err := dumper.Dump(secrets); err != nil {
		return fmt.Errorf("failed to dump secrets: %s", err)
	}

	return nil
}

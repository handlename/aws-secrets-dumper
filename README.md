# aws-secrets-dumper

aws-secrets-dumper is command line tool to initialize managing secrets on AWS.

It supports:

- dump secrets in [AWS Sysetms Manager Parameter Store](https://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/systems-manager-parameter-store.html) or [AWS Secrets Manager](https://docs.aws.amazon.com/ja_jp/secretsmanager/index.html) as YAML formaat
- generate [Terraform](https://www.terraform.io/) files defines and import secrets

## Installation

Download binary from [releases](https://github.com/handlename/aws-secrets-dumper/releases)

## Setup

- Install [sops](https://github.com/mozilla/sops)
    - For encrypt dumped YAML file
- Set up your terraform project
    - Follow [terraform documentation](https://developer.hashicorp.com/terraform/tutorials/aws-get-started)

## Usage

First, dump secrets into row YAML file.

```console
$ aws-secrets-dumper --target secretsmanager -prefix production/ dump > secrets.yml
```

Then, encrypt raw YAML file by sops.

```console
$ sops --encrypt --kms $KMS_KEY_ARN secrets.yml > secrets.encrypted.yml
```

Generate `.tf` file to manage and import secrets by Terraform.

```console
$ aws-secrets-dumper --target ssm -prefix production/ tf | tee secrets.tf
data "sops_file" "ssm_parameters" {
  source_file = "secrets.encrypted.yml"
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
  name        = "production/${each.key}"
  description = nonsensitive(data.sops_file.ssm_parameters.data["${each.value}.description"])
  type        = "SecureString"
  value       = data.sops_file.ssm_parameters.data["${each.value}.value"]
}

import {
  id = "production/SOME_SECRET"
  to = aws_ssm_parameter.parameter["SOME_SECRET"]
}

import {
  id = "production/THAT_ID"
  to = aws_ssm_parameter.parameter["THAT_ID"]
}
```

Finally, run `terraform plan` and check the result.

## Options

```console
$ aws-secrets-dumper -help
NAME:
   aws-secrets-dumper - Management migration helper for secrets on AWS SSM Parameter Store and AWS Secrets Manager with terraform

USAGE:
   main [global options] command [command options] [arguments...]

COMMANDS:
   version  show version
   dump     dump yaml formatted secrets to stdout
   tf       output terraform resource denifition(s) to stdout
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --target value   'ssm' or 'secretsmanager
   --prefix value   secret name prefix
   --remove-prefix  remove prefix from key in dump result (default: false)
   --help, -h       show help (default: false)
```

Run COMMAND with `--help` flag to show helps for each.

## License

see [LICENSE](https://github.com/handlename/aws-secrets-dumper/blob/master/LICENSE) file.

## Author

@handlename (https://github.com/handlename)

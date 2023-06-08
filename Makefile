VERSION=${shell cat ./VERSION}
PROJECT_USERNAME=handlename
PROJECT_REPONAME=aws-secrets-dumper
DIST_DIR=dist

cmd/aws-secrets-dumper/aws-secrets-dumper: *.go */**/*.go
	CGO_ENABLED=0 go build -v -ldflags '-X main.version=$(VERSION)' -o $@ cmd/aws-secrets-dumper/main.go

.PHONY: release
release:
	-git tag v$(VERSION)
	git push
	git push --tags

.PHONY: dist
dist: clean
	CGO_ENABLED=0 goxz \
	  -pv 'v$(VERSION)' \
	  -n aws-secrets-dumper \
	  -build-ldflags '-X main.version=$(VERSION)' \
	  -os='linux,darwin,windows' \
	  -arch='amd64,arm64' \
	  -d $(DIST_DIR) \
	  ./cmd/aws-secrets-dumper

.PHONY: upload
upload: dist
	mkdir -p $(DIST_DIR)
	ghr \
	  -u '$(PROJECT_USERNAME)' \
	  -r '$(PROJECT_REPONAME)' \
	  -prerelease \
	  -replace \
	  'v$(VERSION)' \
	  $(DIST_DIR)

clean:
	rm -rf cmd/aws-secrets-dumper/aws-secrets-dumper $(DIST_DIR)/*

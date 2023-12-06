# Generate Client Interface

This guide describes how to generate clients to interact with ZITADEL.

ZITADEL decided to not check in generated files after v0.104.5.

## Requirements

- docker

## Generate client stub

### PROJECT_PATH

The PROJECT_PATH argument is needed for replacing imports in the generated files.
The path MUST represent the folder where the generated ZITADEL packages will reside in.

This replacement is needed for the message proto.

### TAG_NAME

It's recommended to clone a specific tag. By default, it will use main.

For example: TAG_NAME=v1.0.0

use under project root:

```
DOCKER_BUILDKIT=1 docker build --target zitadel-copy -t zitadel-go:main --build-arg PROJECT_PATH=github.com/zitadel/zitadel-go/v3/pkg/client --build-arg TAG_NAME=main -f build/zitadel/Dockerfile . -o ./pkg/client
``` 

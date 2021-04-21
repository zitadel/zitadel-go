ARG GO_VERSION=1.15.8
ARG NODE_VERSION=15.8.0

#######################
## These steps set platform / arch type specific variables
#######################
FROM alpine AS arm64-base
ENV PROTOC_ARCH aarch_64

FROM alpine AS amd64-base
ENV PROTOC_ARCH x86_64

#######################
## This step sets up the folder structure,
## initalices go mods,
## downloads the protofiles,
## protoc and protoc-gen-grpc-web for later use
#######################
FROM ${BUILDARCH}-base AS base
ARG PROTOC_VERSION=3.13.0
ARG PROTOC_ZIP=protoc-${PROTOC_VERSION}-linux-${PROTOC_ARCH}.zip
ARG TAG_NAME=main


RUN apk add tar curl git
WORKDIR /proto

#protoc
RUN curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/$PROTOC_ZIP \
    && unzip -o $PROTOC_ZIP -d /usr/local bin/protoc \
    && unzip -o $PROTOC_ZIP -d /proto include/* \
    && rm -f $PROTOC_ZIP

#proto dependencies
RUN curl https://raw.githubusercontent.com/envoyproxy/protoc-gen-validate/v0.4.1/validate/validate.proto --create-dirs -o include/validate/validate.proto  \
    && curl https://raw.githubusercontent.com/grpc-ecosystem/grpc-gateway/v2.2.0/protoc-gen-openapiv2/options/annotations.proto --create-dirs -o include/protoc-gen-openapiv2/options/annotations.proto \
    && curl https://raw.githubusercontent.com/grpc-ecosystem/grpc-gateway/v2.2.0/protoc-gen-openapiv2/options/openapiv2.proto --create-dirs -o include/protoc-gen-openapiv2/options/openapiv2.proto \
    && curl https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/annotations.proto --create-dirs -o include/google/api/annotations.proto \
    && curl https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/http.proto --create-dirs -o include/google/api/http.proto \
    && curl https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/field_behavior.proto --create-dirs -o include/google/api/field_behavior.proto

WORKDIR /zitadel
RUN git clone --depth 1 -b ${TAG_NAME} https://github.com/caos/zitadel . \
    && cp -r proto/* /proto/include \
    && cp -r internal/protoc/protoc-gen-authoption/authoption /proto/include

#######################
## Go dependencies
## Speed up this step by mounting your local go mod pkg directory
#######################
FROM golang:${GO_VERSION} as go-dep
COPY --from=base /proto/include /proto/include

WORKDIR /go/src/github.com/caos/zitadel-go
COPY tools ./tools
COPY ./go.* .

RUN go mod download
RUN ./tools/install.sh

#######################
## Go base build
#######################
FROM go-dep as zitadel-client
ARG PROJECT_PATH

COPY --from=base /proto /proto
COPY --from=base /usr/local/bin /usr/local/bin/.

COPY build/zitadel/generate-grpc-client.sh build/zitadel/generate-grpc-client.sh
RUN mkdir -p /go/src/github.com/caos/zitadel/pkg/grpc/authoption
## generate all pb files and copy them to a new directory
RUN ./build/zitadel/generate-grpc-client.sh ${PROJECT_PATH} \
    && mkdir /zitadel-api \
    && find /go/src/github.com/caos/zitadel/pkg/grpc -iname '*.pb.go' -exec cp --parents \{\} /zitadel-api \;


#######################
## prepare generated files for output
#######################
FROM scratch as zitadel-copy
ARG PROJECT_PATH
COPY --from=zitadel-client /zitadel-api/go/src/github.com/caos/zitadel/pkg/grpc /zitadel
ARG GO_VERSION=1.19

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
ARG PROTOC_VERSION=3.18.0
ARG PROTOC_ZIP=protoc-${PROTOC_VERSION}-linux-${PROTOC_ARCH}.zip
ARG GATEWAY_VERSION=2.15.2
ARG VALIDATOR_VERSION=0.9.1
ARG TAG_NAME=main


RUN apk add tar curl git
WORKDIR /proto

#protoc
RUN curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/$PROTOC_ZIP \
    && unzip -o $PROTOC_ZIP -d /usr/local bin/protoc \
    && unzip -o $PROTOC_ZIP -d /proto include/* \
    && rm -f $PROTOC_ZIP

#proto dependencies
RUN curl https://raw.githubusercontent.com/envoyproxy/protoc-gen-validate/v${VALIDATOR_VERSION}/validate/validate.proto --create-dirs -o include/validate/validate.proto  \
    && curl https://raw.githubusercontent.com/grpc-ecosystem/grpc-gateway/v${GATEWAY_VERSION}/protoc-gen-openapiv2/options/annotations.proto --create-dirs -o include/protoc-gen-openapiv2/options/annotations.proto \
    && curl https://raw.githubusercontent.com/grpc-ecosystem/grpc-gateway/v${GATEWAY_VERSION}/protoc-gen-openapiv2/options/openapiv2.proto --create-dirs -o include/protoc-gen-openapiv2/options/openapiv2.proto \
    && curl https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/annotations.proto --create-dirs -o include/google/api/annotations.proto \
    && curl https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/http.proto --create-dirs -o include/google/api/http.proto \
    && curl https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/field_behavior.proto --create-dirs -o include/google/api/field_behavior.proto

WORKDIR /zitadel
RUN git clone --depth 1 -b ${TAG_NAME} https://github.com/zitadel/zitadel . \
    && cp -r proto/* /proto/include \
    && cp -r internal/protoc/protoc-gen-authoption/authoption /proto/include

#######################
## Go dependencies
## Speed up this step by mounting your local go mod pkg directory
#######################
FROM golang:${GO_VERSION} as go-dep
COPY --from=base /proto/include /proto/include

WORKDIR /go/src/github.com/zitadel/zitadel-go
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1

#######################
## Go base build
#######################
FROM go-dep as zitadel-client
ARG PROJECT_PATH=github.com/zitadel/zitadel-go/v2/pkg/client

COPY --from=base /proto /proto
COPY --from=base /usr/local/bin /usr/local/bin/.

COPY build/zitadel/generate-grpc-client.sh build/zitadel/generate-grpc-client.sh
RUN mkdir -p /go/src/github.com/zitadel/zitadel/pkg/grpc/authoption
## generate all pb files and copy them to a new directory
RUN ./build/zitadel/generate-grpc-client.sh ${PROJECT_PATH} \
    && mkdir /zitadel-api \
    && find /go/src/${PROJECT_PATH}/zitadel -iname '*.pb.go' -exec cp --parents \{\} /zitadel-api \; \
    && mv /go/src/github.com/zitadel/zitadel/pkg/grpc/admin/admin_grpc.pb.go /zitadel-api/go/src/${PROJECT_PATH}/zitadel/admin/ \
    && mv /go/src/github.com/zitadel/zitadel/pkg/grpc/auth/auth_grpc.pb.go /zitadel-api/go/src/${PROJECT_PATH}/zitadel/auth/ \
    && mv /go/src/github.com/zitadel/zitadel/pkg/grpc/management/management_grpc.pb.go /zitadel-api/go/src/${PROJECT_PATH}/zitadel/management/ \
    && mv /go/src/github.com/zitadel/zitadel/pkg/grpc/system/system_grpc.pb.go /zitadel-api/go/src/${PROJECT_PATH}/zitadel/system/ \
    && mv /go/src/github.com/zitadel/zitadel/pkg/grpc/session/v2beta/*.pb.go /zitadel-api/go/src/${PROJECT_PATH}/zitadel/session/v2beta/
    #######################
## prepare generated files for output
#######################
FROM scratch as zitadel-copy
ARG PROJECT_PATH=github.com/zitadel/zitadel-go/v2/pkg/client
COPY --from=zitadel-client /zitadel-api/go/src/${PROJECT_PATH}/zitadel /zitadel

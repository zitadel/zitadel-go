package middleware

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/caos/zitadel-go/pkg/client"
)

type OrgInterceptor struct {
	orgID string
}

//NewOrgInterceptor statically set the organisation context for every call
//
//If you need to switch between multiple organisations for different requests, use the SetOrgID function
//directly on your calls (see example/mgmt/mgmt.go)
func NewOrgInterceptor(orgID string) *OrgInterceptor {
	return &OrgInterceptor{
		orgID: orgID,
	}
}

func (interceptor *OrgInterceptor) Unary() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(SetOrgID(ctx, interceptor.orgID), method, req, reply, cc, opts...)
	}
}

func (interceptor *OrgInterceptor) Stream() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(SetOrgID(ctx, interceptor.orgID), desc, cc, method, opts...)
	}
}

//SetOrgID passes the orgID used for the organization context (where the api calls are executed)
func SetOrgID(ctx context.Context, orgID string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, client.OrgHeader, orgID)
}

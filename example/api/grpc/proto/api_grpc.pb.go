// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: api.proto

package v3alpha

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	ExampleService_Public_FullMethodName             = "/zitadel.go.example.api.v3alpha.ExampleService/Public"
	ExampleService_Protected_FullMethodName          = "/zitadel.go.example.api.v3alpha.ExampleService/Protected"
	ExampleService_ProtectedAdmin_FullMethodName     = "/zitadel.go.example.api.v3alpha.ExampleService/ProtectedAdmin"
	ExampleService_ClientStream_FullMethodName       = "/zitadel.go.example.api.v3alpha.ExampleService/ClientStream"
	ExampleService_ServerStream_FullMethodName       = "/zitadel.go.example.api.v3alpha.ExampleService/ServerStream"
	ExampleService_ClientServerStream_FullMethodName = "/zitadel.go.example.api.v3alpha.ExampleService/ClientServerStream"
)

// ExampleServiceClient is the client API for ExampleService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ExampleServiceClient interface {
	Public(ctx context.Context, in *PublicRequest, opts ...grpc.CallOption) (*PublicResponse, error)
	Protected(ctx context.Context, in *ProtectedRequest, opts ...grpc.CallOption) (*ProtectedResponse, error)
	ProtectedAdmin(ctx context.Context, in *ProtectedAdminRequest, opts ...grpc.CallOption) (*ProtectedAdminResponse, error)
	ClientStream(ctx context.Context, opts ...grpc.CallOption) (ExampleService_ClientStreamClient, error)
	ServerStream(ctx context.Context, in *ServerStreamRequest, opts ...grpc.CallOption) (ExampleService_ServerStreamClient, error)
	ClientServerStream(ctx context.Context, opts ...grpc.CallOption) (ExampleService_ClientServerStreamClient, error)
}

type exampleServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewExampleServiceClient(cc grpc.ClientConnInterface) ExampleServiceClient {
	return &exampleServiceClient{cc}
}

func (c *exampleServiceClient) Public(ctx context.Context, in *PublicRequest, opts ...grpc.CallOption) (*PublicResponse, error) {
	out := new(PublicResponse)
	err := c.cc.Invoke(ctx, ExampleService_Public_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *exampleServiceClient) Protected(ctx context.Context, in *ProtectedRequest, opts ...grpc.CallOption) (*ProtectedResponse, error) {
	out := new(ProtectedResponse)
	err := c.cc.Invoke(ctx, ExampleService_Protected_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *exampleServiceClient) ProtectedAdmin(ctx context.Context, in *ProtectedAdminRequest, opts ...grpc.CallOption) (*ProtectedAdminResponse, error) {
	out := new(ProtectedAdminResponse)
	err := c.cc.Invoke(ctx, ExampleService_ProtectedAdmin_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *exampleServiceClient) ClientStream(ctx context.Context, opts ...grpc.CallOption) (ExampleService_ClientStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &ExampleService_ServiceDesc.Streams[0], ExampleService_ClientStream_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &exampleServiceClientStreamClient{stream}
	return x, nil
}

type ExampleService_ClientStreamClient interface {
	Send(*ClientStreamRequest) error
	CloseAndRecv() (*ClientStreamResponse, error)
	grpc.ClientStream
}

type exampleServiceClientStreamClient struct {
	grpc.ClientStream
}

func (x *exampleServiceClientStreamClient) Send(m *ClientStreamRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *exampleServiceClientStreamClient) CloseAndRecv() (*ClientStreamResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(ClientStreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *exampleServiceClient) ServerStream(ctx context.Context, in *ServerStreamRequest, opts ...grpc.CallOption) (ExampleService_ServerStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &ExampleService_ServiceDesc.Streams[1], ExampleService_ServerStream_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &exampleServiceServerStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type ExampleService_ServerStreamClient interface {
	Recv() (*ServerStreamResponse, error)
	grpc.ClientStream
}

type exampleServiceServerStreamClient struct {
	grpc.ClientStream
}

func (x *exampleServiceServerStreamClient) Recv() (*ServerStreamResponse, error) {
	m := new(ServerStreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *exampleServiceClient) ClientServerStream(ctx context.Context, opts ...grpc.CallOption) (ExampleService_ClientServerStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &ExampleService_ServiceDesc.Streams[2], ExampleService_ClientServerStream_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &exampleServiceClientServerStreamClient{stream}
	return x, nil
}

type ExampleService_ClientServerStreamClient interface {
	Send(*ClientServerStreamRequest) error
	Recv() (*ClientServerStreamResponse, error)
	grpc.ClientStream
}

type exampleServiceClientServerStreamClient struct {
	grpc.ClientStream
}

func (x *exampleServiceClientServerStreamClient) Send(m *ClientServerStreamRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *exampleServiceClientServerStreamClient) Recv() (*ClientServerStreamResponse, error) {
	m := new(ClientServerStreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ExampleServiceServer is the server API for ExampleService service.
// All implementations must embed UnimplementedExampleServiceServer
// for forward compatibility
type ExampleServiceServer interface {
	Public(context.Context, *PublicRequest) (*PublicResponse, error)
	Protected(context.Context, *ProtectedRequest) (*ProtectedResponse, error)
	ProtectedAdmin(context.Context, *ProtectedAdminRequest) (*ProtectedAdminResponse, error)
	ClientStream(ExampleService_ClientStreamServer) error
	ServerStream(*ServerStreamRequest, ExampleService_ServerStreamServer) error
	ClientServerStream(ExampleService_ClientServerStreamServer) error
	mustEmbedUnimplementedExampleServiceServer()
}

// UnimplementedExampleServiceServer must be embedded to have forward compatible implementations.
type UnimplementedExampleServiceServer struct {
}

func (UnimplementedExampleServiceServer) Public(context.Context, *PublicRequest) (*PublicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Public not implemented")
}
func (UnimplementedExampleServiceServer) Protected(context.Context, *ProtectedRequest) (*ProtectedResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Protected not implemented")
}
func (UnimplementedExampleServiceServer) ProtectedAdmin(context.Context, *ProtectedAdminRequest) (*ProtectedAdminResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ProtectedAdmin not implemented")
}
func (UnimplementedExampleServiceServer) ClientStream(ExampleService_ClientStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method ClientStream not implemented")
}
func (UnimplementedExampleServiceServer) ServerStream(*ServerStreamRequest, ExampleService_ServerStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method ServerStream not implemented")
}
func (UnimplementedExampleServiceServer) ClientServerStream(ExampleService_ClientServerStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method ClientServerStream not implemented")
}
func (UnimplementedExampleServiceServer) mustEmbedUnimplementedExampleServiceServer() {}

// UnsafeExampleServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ExampleServiceServer will
// result in compilation errors.
type UnsafeExampleServiceServer interface {
	mustEmbedUnimplementedExampleServiceServer()
}

func RegisterExampleServiceServer(s grpc.ServiceRegistrar, srv ExampleServiceServer) {
	s.RegisterService(&ExampleService_ServiceDesc, srv)
}

func _ExampleService_Public_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PublicRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExampleServiceServer).Public(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExampleService_Public_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExampleServiceServer).Public(ctx, req.(*PublicRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExampleService_Protected_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProtectedRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExampleServiceServer).Protected(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExampleService_Protected_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExampleServiceServer).Protected(ctx, req.(*ProtectedRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExampleService_ProtectedAdmin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProtectedAdminRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExampleServiceServer).ProtectedAdmin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExampleService_ProtectedAdmin_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExampleServiceServer).ProtectedAdmin(ctx, req.(*ProtectedAdminRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExampleService_ClientStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ExampleServiceServer).ClientStream(&exampleServiceClientStreamServer{stream})
}

type ExampleService_ClientStreamServer interface {
	SendAndClose(*ClientStreamResponse) error
	Recv() (*ClientStreamRequest, error)
	grpc.ServerStream
}

type exampleServiceClientStreamServer struct {
	grpc.ServerStream
}

func (x *exampleServiceClientStreamServer) SendAndClose(m *ClientStreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *exampleServiceClientStreamServer) Recv() (*ClientStreamRequest, error) {
	m := new(ClientStreamRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _ExampleService_ServerStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ServerStreamRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ExampleServiceServer).ServerStream(m, &exampleServiceServerStreamServer{stream})
}

type ExampleService_ServerStreamServer interface {
	Send(*ServerStreamResponse) error
	grpc.ServerStream
}

type exampleServiceServerStreamServer struct {
	grpc.ServerStream
}

func (x *exampleServiceServerStreamServer) Send(m *ServerStreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _ExampleService_ClientServerStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ExampleServiceServer).ClientServerStream(&exampleServiceClientServerStreamServer{stream})
}

type ExampleService_ClientServerStreamServer interface {
	Send(*ClientServerStreamResponse) error
	Recv() (*ClientServerStreamRequest, error)
	grpc.ServerStream
}

type exampleServiceClientServerStreamServer struct {
	grpc.ServerStream
}

func (x *exampleServiceClientServerStreamServer) Send(m *ClientServerStreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *exampleServiceClientServerStreamServer) Recv() (*ClientServerStreamRequest, error) {
	m := new(ClientServerStreamRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ExampleService_ServiceDesc is the grpc.ServiceDesc for ExampleService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ExampleService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "zitadel.go.example.api.v3alpha.ExampleService",
	HandlerType: (*ExampleServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Public",
			Handler:    _ExampleService_Public_Handler,
		},
		{
			MethodName: "Protected",
			Handler:    _ExampleService_Protected_Handler,
		},
		{
			MethodName: "ProtectedAdmin",
			Handler:    _ExampleService_ProtectedAdmin_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ClientStream",
			Handler:       _ExampleService_ClientStream_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "ServerStream",
			Handler:       _ExampleService_ServerStream_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "ClientServerStream",
			Handler:       _ExampleService_ClientServerStream_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "api.proto",
}
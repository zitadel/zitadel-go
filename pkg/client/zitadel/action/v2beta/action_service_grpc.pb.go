// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.25.1
// source: zitadel/action/v2beta/action_service.proto

package action

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
	ActionService_CreateTarget_FullMethodName           = "/zitadel.action.v2beta.ActionService/CreateTarget"
	ActionService_UpdateTarget_FullMethodName           = "/zitadel.action.v2beta.ActionService/UpdateTarget"
	ActionService_DeleteTarget_FullMethodName           = "/zitadel.action.v2beta.ActionService/DeleteTarget"
	ActionService_GetTarget_FullMethodName              = "/zitadel.action.v2beta.ActionService/GetTarget"
	ActionService_ListTargets_FullMethodName            = "/zitadel.action.v2beta.ActionService/ListTargets"
	ActionService_SetExecution_FullMethodName           = "/zitadel.action.v2beta.ActionService/SetExecution"
	ActionService_ListExecutions_FullMethodName         = "/zitadel.action.v2beta.ActionService/ListExecutions"
	ActionService_ListExecutionFunctions_FullMethodName = "/zitadel.action.v2beta.ActionService/ListExecutionFunctions"
	ActionService_ListExecutionMethods_FullMethodName   = "/zitadel.action.v2beta.ActionService/ListExecutionMethods"
	ActionService_ListExecutionServices_FullMethodName  = "/zitadel.action.v2beta.ActionService/ListExecutionServices"
)

// ActionServiceClient is the client API for ActionService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ActionServiceClient interface {
	// Create Target
	//
	// Create a new target to your endpoint, which can be used in executions.
	//
	// Required permission:
	//   - `action.target.write`
	//
	// Required feature flag:
	//   - `actions`
	CreateTarget(ctx context.Context, in *CreateTargetRequest, opts ...grpc.CallOption) (*CreateTargetResponse, error)
	// Update Target
	//
	// Update an existing target.
	// To generate a new signing key set the optional expirationSigningKey.
	//
	// Required permission:
	//   - `action.target.write`
	//
	// Required feature flag:
	//   - `actions`
	UpdateTarget(ctx context.Context, in *UpdateTargetRequest, opts ...grpc.CallOption) (*UpdateTargetResponse, error)
	// Delete Target
	//
	// Delete an existing target. This will remove it from any configured execution as well.
	// In case the target is not found, the request will return a successful response as
	// the desired state is already achieved.
	//
	// Required permission:
	//   - `action.target.delete`
	//
	// Required feature flag:
	//   - `actions`
	DeleteTarget(ctx context.Context, in *DeleteTargetRequest, opts ...grpc.CallOption) (*DeleteTargetResponse, error)
	// Get Target
	//
	// Returns the target identified by the requested ID.
	//
	// Required permission:
	//   - `action.target.read`
	//
	// Required feature flag:
	//   - `actions`
	GetTarget(ctx context.Context, in *GetTargetRequest, opts ...grpc.CallOption) (*GetTargetResponse, error)
	// List targets
	//
	// List all matching targets. By default all targets of the instance are returned.
	// Make sure to include a limit and sorting for pagination.
	//
	// Required permission:
	//   - `action.target.read`
	//
	// Required feature flag:
	//   - `actions`
	ListTargets(ctx context.Context, in *ListTargetsRequest, opts ...grpc.CallOption) (*ListTargetsResponse, error)
	// Set Execution
	//
	// Sets an execution to call a target or include the targets of another execution.
	// Setting an empty list of targets will remove all targets from the execution, making it a noop.
	//
	// Required permission:
	//   - `action.execution.write`
	//
	// Required feature flag:
	//   - `actions`
	SetExecution(ctx context.Context, in *SetExecutionRequest, opts ...grpc.CallOption) (*SetExecutionResponse, error)
	// List Executions
	//
	// List all matching executions. By default all executions of the instance are returned that have at least one execution target.
	// Make sure to include a limit and sorting for pagination.
	//
	// Required permission:
	//   - `action.execution.read`
	//
	// Required feature flag:
	//   - `actions`
	ListExecutions(ctx context.Context, in *ListExecutionsRequest, opts ...grpc.CallOption) (*ListExecutionsResponse, error)
	// List Execution Functions
	//
	// List all available functions which can be used as condition for executions.
	ListExecutionFunctions(ctx context.Context, in *ListExecutionFunctionsRequest, opts ...grpc.CallOption) (*ListExecutionFunctionsResponse, error)
	// List Execution Methods
	//
	// List all available methods which can be used as condition for executions.
	ListExecutionMethods(ctx context.Context, in *ListExecutionMethodsRequest, opts ...grpc.CallOption) (*ListExecutionMethodsResponse, error)
	// List Execution Services
	//
	// List all available services which can be used as condition for executions.
	ListExecutionServices(ctx context.Context, in *ListExecutionServicesRequest, opts ...grpc.CallOption) (*ListExecutionServicesResponse, error)
}

type actionServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewActionServiceClient(cc grpc.ClientConnInterface) ActionServiceClient {
	return &actionServiceClient{cc}
}

func (c *actionServiceClient) CreateTarget(ctx context.Context, in *CreateTargetRequest, opts ...grpc.CallOption) (*CreateTargetResponse, error) {
	out := new(CreateTargetResponse)
	err := c.cc.Invoke(ctx, ActionService_CreateTarget_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *actionServiceClient) UpdateTarget(ctx context.Context, in *UpdateTargetRequest, opts ...grpc.CallOption) (*UpdateTargetResponse, error) {
	out := new(UpdateTargetResponse)
	err := c.cc.Invoke(ctx, ActionService_UpdateTarget_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *actionServiceClient) DeleteTarget(ctx context.Context, in *DeleteTargetRequest, opts ...grpc.CallOption) (*DeleteTargetResponse, error) {
	out := new(DeleteTargetResponse)
	err := c.cc.Invoke(ctx, ActionService_DeleteTarget_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *actionServiceClient) GetTarget(ctx context.Context, in *GetTargetRequest, opts ...grpc.CallOption) (*GetTargetResponse, error) {
	out := new(GetTargetResponse)
	err := c.cc.Invoke(ctx, ActionService_GetTarget_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *actionServiceClient) ListTargets(ctx context.Context, in *ListTargetsRequest, opts ...grpc.CallOption) (*ListTargetsResponse, error) {
	out := new(ListTargetsResponse)
	err := c.cc.Invoke(ctx, ActionService_ListTargets_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *actionServiceClient) SetExecution(ctx context.Context, in *SetExecutionRequest, opts ...grpc.CallOption) (*SetExecutionResponse, error) {
	out := new(SetExecutionResponse)
	err := c.cc.Invoke(ctx, ActionService_SetExecution_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *actionServiceClient) ListExecutions(ctx context.Context, in *ListExecutionsRequest, opts ...grpc.CallOption) (*ListExecutionsResponse, error) {
	out := new(ListExecutionsResponse)
	err := c.cc.Invoke(ctx, ActionService_ListExecutions_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *actionServiceClient) ListExecutionFunctions(ctx context.Context, in *ListExecutionFunctionsRequest, opts ...grpc.CallOption) (*ListExecutionFunctionsResponse, error) {
	out := new(ListExecutionFunctionsResponse)
	err := c.cc.Invoke(ctx, ActionService_ListExecutionFunctions_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *actionServiceClient) ListExecutionMethods(ctx context.Context, in *ListExecutionMethodsRequest, opts ...grpc.CallOption) (*ListExecutionMethodsResponse, error) {
	out := new(ListExecutionMethodsResponse)
	err := c.cc.Invoke(ctx, ActionService_ListExecutionMethods_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *actionServiceClient) ListExecutionServices(ctx context.Context, in *ListExecutionServicesRequest, opts ...grpc.CallOption) (*ListExecutionServicesResponse, error) {
	out := new(ListExecutionServicesResponse)
	err := c.cc.Invoke(ctx, ActionService_ListExecutionServices_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ActionServiceServer is the server API for ActionService service.
// All implementations must embed UnimplementedActionServiceServer
// for forward compatibility
type ActionServiceServer interface {
	// Create Target
	//
	// Create a new target to your endpoint, which can be used in executions.
	//
	// Required permission:
	//   - `action.target.write`
	//
	// Required feature flag:
	//   - `actions`
	CreateTarget(context.Context, *CreateTargetRequest) (*CreateTargetResponse, error)
	// Update Target
	//
	// Update an existing target.
	// To generate a new signing key set the optional expirationSigningKey.
	//
	// Required permission:
	//   - `action.target.write`
	//
	// Required feature flag:
	//   - `actions`
	UpdateTarget(context.Context, *UpdateTargetRequest) (*UpdateTargetResponse, error)
	// Delete Target
	//
	// Delete an existing target. This will remove it from any configured execution as well.
	// In case the target is not found, the request will return a successful response as
	// the desired state is already achieved.
	//
	// Required permission:
	//   - `action.target.delete`
	//
	// Required feature flag:
	//   - `actions`
	DeleteTarget(context.Context, *DeleteTargetRequest) (*DeleteTargetResponse, error)
	// Get Target
	//
	// Returns the target identified by the requested ID.
	//
	// Required permission:
	//   - `action.target.read`
	//
	// Required feature flag:
	//   - `actions`
	GetTarget(context.Context, *GetTargetRequest) (*GetTargetResponse, error)
	// List targets
	//
	// List all matching targets. By default all targets of the instance are returned.
	// Make sure to include a limit and sorting for pagination.
	//
	// Required permission:
	//   - `action.target.read`
	//
	// Required feature flag:
	//   - `actions`
	ListTargets(context.Context, *ListTargetsRequest) (*ListTargetsResponse, error)
	// Set Execution
	//
	// Sets an execution to call a target or include the targets of another execution.
	// Setting an empty list of targets will remove all targets from the execution, making it a noop.
	//
	// Required permission:
	//   - `action.execution.write`
	//
	// Required feature flag:
	//   - `actions`
	SetExecution(context.Context, *SetExecutionRequest) (*SetExecutionResponse, error)
	// List Executions
	//
	// List all matching executions. By default all executions of the instance are returned that have at least one execution target.
	// Make sure to include a limit and sorting for pagination.
	//
	// Required permission:
	//   - `action.execution.read`
	//
	// Required feature flag:
	//   - `actions`
	ListExecutions(context.Context, *ListExecutionsRequest) (*ListExecutionsResponse, error)
	// List Execution Functions
	//
	// List all available functions which can be used as condition for executions.
	ListExecutionFunctions(context.Context, *ListExecutionFunctionsRequest) (*ListExecutionFunctionsResponse, error)
	// List Execution Methods
	//
	// List all available methods which can be used as condition for executions.
	ListExecutionMethods(context.Context, *ListExecutionMethodsRequest) (*ListExecutionMethodsResponse, error)
	// List Execution Services
	//
	// List all available services which can be used as condition for executions.
	ListExecutionServices(context.Context, *ListExecutionServicesRequest) (*ListExecutionServicesResponse, error)
	mustEmbedUnimplementedActionServiceServer()
}

// UnimplementedActionServiceServer must be embedded to have forward compatible implementations.
type UnimplementedActionServiceServer struct {
}

func (UnimplementedActionServiceServer) CreateTarget(context.Context, *CreateTargetRequest) (*CreateTargetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateTarget not implemented")
}
func (UnimplementedActionServiceServer) UpdateTarget(context.Context, *UpdateTargetRequest) (*UpdateTargetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateTarget not implemented")
}
func (UnimplementedActionServiceServer) DeleteTarget(context.Context, *DeleteTargetRequest) (*DeleteTargetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteTarget not implemented")
}
func (UnimplementedActionServiceServer) GetTarget(context.Context, *GetTargetRequest) (*GetTargetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTarget not implemented")
}
func (UnimplementedActionServiceServer) ListTargets(context.Context, *ListTargetsRequest) (*ListTargetsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListTargets not implemented")
}
func (UnimplementedActionServiceServer) SetExecution(context.Context, *SetExecutionRequest) (*SetExecutionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetExecution not implemented")
}
func (UnimplementedActionServiceServer) ListExecutions(context.Context, *ListExecutionsRequest) (*ListExecutionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListExecutions not implemented")
}
func (UnimplementedActionServiceServer) ListExecutionFunctions(context.Context, *ListExecutionFunctionsRequest) (*ListExecutionFunctionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListExecutionFunctions not implemented")
}
func (UnimplementedActionServiceServer) ListExecutionMethods(context.Context, *ListExecutionMethodsRequest) (*ListExecutionMethodsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListExecutionMethods not implemented")
}
func (UnimplementedActionServiceServer) ListExecutionServices(context.Context, *ListExecutionServicesRequest) (*ListExecutionServicesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListExecutionServices not implemented")
}
func (UnimplementedActionServiceServer) mustEmbedUnimplementedActionServiceServer() {}

// UnsafeActionServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ActionServiceServer will
// result in compilation errors.
type UnsafeActionServiceServer interface {
	mustEmbedUnimplementedActionServiceServer()
}

func RegisterActionServiceServer(s grpc.ServiceRegistrar, srv ActionServiceServer) {
	s.RegisterService(&ActionService_ServiceDesc, srv)
}

func _ActionService_CreateTarget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTargetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ActionServiceServer).CreateTarget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ActionService_CreateTarget_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ActionServiceServer).CreateTarget(ctx, req.(*CreateTargetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ActionService_UpdateTarget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateTargetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ActionServiceServer).UpdateTarget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ActionService_UpdateTarget_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ActionServiceServer).UpdateTarget(ctx, req.(*UpdateTargetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ActionService_DeleteTarget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteTargetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ActionServiceServer).DeleteTarget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ActionService_DeleteTarget_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ActionServiceServer).DeleteTarget(ctx, req.(*DeleteTargetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ActionService_GetTarget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetTargetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ActionServiceServer).GetTarget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ActionService_GetTarget_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ActionServiceServer).GetTarget(ctx, req.(*GetTargetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ActionService_ListTargets_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListTargetsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ActionServiceServer).ListTargets(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ActionService_ListTargets_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ActionServiceServer).ListTargets(ctx, req.(*ListTargetsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ActionService_SetExecution_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetExecutionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ActionServiceServer).SetExecution(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ActionService_SetExecution_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ActionServiceServer).SetExecution(ctx, req.(*SetExecutionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ActionService_ListExecutions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListExecutionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ActionServiceServer).ListExecutions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ActionService_ListExecutions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ActionServiceServer).ListExecutions(ctx, req.(*ListExecutionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ActionService_ListExecutionFunctions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListExecutionFunctionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ActionServiceServer).ListExecutionFunctions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ActionService_ListExecutionFunctions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ActionServiceServer).ListExecutionFunctions(ctx, req.(*ListExecutionFunctionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ActionService_ListExecutionMethods_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListExecutionMethodsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ActionServiceServer).ListExecutionMethods(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ActionService_ListExecutionMethods_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ActionServiceServer).ListExecutionMethods(ctx, req.(*ListExecutionMethodsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ActionService_ListExecutionServices_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListExecutionServicesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ActionServiceServer).ListExecutionServices(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ActionService_ListExecutionServices_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ActionServiceServer).ListExecutionServices(ctx, req.(*ListExecutionServicesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ActionService_ServiceDesc is the grpc.ServiceDesc for ActionService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ActionService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "zitadel.action.v2beta.ActionService",
	HandlerType: (*ActionServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateTarget",
			Handler:    _ActionService_CreateTarget_Handler,
		},
		{
			MethodName: "UpdateTarget",
			Handler:    _ActionService_UpdateTarget_Handler,
		},
		{
			MethodName: "DeleteTarget",
			Handler:    _ActionService_DeleteTarget_Handler,
		},
		{
			MethodName: "GetTarget",
			Handler:    _ActionService_GetTarget_Handler,
		},
		{
			MethodName: "ListTargets",
			Handler:    _ActionService_ListTargets_Handler,
		},
		{
			MethodName: "SetExecution",
			Handler:    _ActionService_SetExecution_Handler,
		},
		{
			MethodName: "ListExecutions",
			Handler:    _ActionService_ListExecutions_Handler,
		},
		{
			MethodName: "ListExecutionFunctions",
			Handler:    _ActionService_ListExecutionFunctions_Handler,
		},
		{
			MethodName: "ListExecutionMethods",
			Handler:    _ActionService_ListExecutionMethods_Handler,
		},
		{
			MethodName: "ListExecutionServices",
			Handler:    _ActionService_ListExecutionServices_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "zitadel/action/v2beta/action_service.proto",
}

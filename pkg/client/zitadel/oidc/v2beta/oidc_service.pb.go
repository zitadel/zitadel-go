// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.18.0
// source: zitadel/oidc/v2beta/oidc_service.proto

package oidc

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	v2beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2beta"
	_ "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/protoc/v2"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetAuthRequestRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthRequestId string `protobuf:"bytes,1,opt,name=auth_request_id,json=authRequestId,proto3" json:"auth_request_id,omitempty"`
}

func (x *GetAuthRequestRequest) Reset() {
	*x = GetAuthRequestRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAuthRequestRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAuthRequestRequest) ProtoMessage() {}

func (x *GetAuthRequestRequest) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAuthRequestRequest.ProtoReflect.Descriptor instead.
func (*GetAuthRequestRequest) Descriptor() ([]byte, []int) {
	return file_zitadel_oidc_v2beta_oidc_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetAuthRequestRequest) GetAuthRequestId() string {
	if x != nil {
		return x.AuthRequestId
	}
	return ""
}

type GetAuthRequestResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthRequest *AuthRequest `protobuf:"bytes,1,opt,name=auth_request,json=authRequest,proto3" json:"auth_request,omitempty"`
}

func (x *GetAuthRequestResponse) Reset() {
	*x = GetAuthRequestResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAuthRequestResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAuthRequestResponse) ProtoMessage() {}

func (x *GetAuthRequestResponse) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAuthRequestResponse.ProtoReflect.Descriptor instead.
func (*GetAuthRequestResponse) Descriptor() ([]byte, []int) {
	return file_zitadel_oidc_v2beta_oidc_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetAuthRequestResponse) GetAuthRequest() *AuthRequest {
	if x != nil {
		return x.AuthRequest
	}
	return nil
}

type CreateCallbackRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthRequestId string `protobuf:"bytes,1,opt,name=auth_request_id,json=authRequestId,proto3" json:"auth_request_id,omitempty"`
	// Types that are assignable to CallbackKind:
	//
	//	*CreateCallbackRequest_Session
	//	*CreateCallbackRequest_Error
	CallbackKind isCreateCallbackRequest_CallbackKind `protobuf_oneof:"callback_kind"`
}

func (x *CreateCallbackRequest) Reset() {
	*x = CreateCallbackRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateCallbackRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateCallbackRequest) ProtoMessage() {}

func (x *CreateCallbackRequest) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateCallbackRequest.ProtoReflect.Descriptor instead.
func (*CreateCallbackRequest) Descriptor() ([]byte, []int) {
	return file_zitadel_oidc_v2beta_oidc_service_proto_rawDescGZIP(), []int{2}
}

func (x *CreateCallbackRequest) GetAuthRequestId() string {
	if x != nil {
		return x.AuthRequestId
	}
	return ""
}

func (m *CreateCallbackRequest) GetCallbackKind() isCreateCallbackRequest_CallbackKind {
	if m != nil {
		return m.CallbackKind
	}
	return nil
}

func (x *CreateCallbackRequest) GetSession() *Session {
	if x, ok := x.GetCallbackKind().(*CreateCallbackRequest_Session); ok {
		return x.Session
	}
	return nil
}

func (x *CreateCallbackRequest) GetError() *AuthorizationError {
	if x, ok := x.GetCallbackKind().(*CreateCallbackRequest_Error); ok {
		return x.Error
	}
	return nil
}

type isCreateCallbackRequest_CallbackKind interface {
	isCreateCallbackRequest_CallbackKind()
}

type CreateCallbackRequest_Session struct {
	Session *Session `protobuf:"bytes,2,opt,name=session,proto3,oneof"`
}

type CreateCallbackRequest_Error struct {
	Error *AuthorizationError `protobuf:"bytes,3,opt,name=error,proto3,oneof"`
}

func (*CreateCallbackRequest_Session) isCreateCallbackRequest_CallbackKind() {}

func (*CreateCallbackRequest_Error) isCreateCallbackRequest_CallbackKind() {}

type Session struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SessionId    string `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	SessionToken string `protobuf:"bytes,2,opt,name=session_token,json=sessionToken,proto3" json:"session_token,omitempty"`
}

func (x *Session) Reset() {
	*x = Session{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Session) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Session) ProtoMessage() {}

func (x *Session) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Session.ProtoReflect.Descriptor instead.
func (*Session) Descriptor() ([]byte, []int) {
	return file_zitadel_oidc_v2beta_oidc_service_proto_rawDescGZIP(), []int{3}
}

func (x *Session) GetSessionId() string {
	if x != nil {
		return x.SessionId
	}
	return ""
}

func (x *Session) GetSessionToken() string {
	if x != nil {
		return x.SessionToken
	}
	return ""
}

type CreateCallbackResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Details     *v2beta.Details `protobuf:"bytes,1,opt,name=details,proto3" json:"details,omitempty"`
	CallbackUrl string          `protobuf:"bytes,2,opt,name=callback_url,json=callbackUrl,proto3" json:"callback_url,omitempty"`
}

func (x *CreateCallbackResponse) Reset() {
	*x = CreateCallbackResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateCallbackResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateCallbackResponse) ProtoMessage() {}

func (x *CreateCallbackResponse) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateCallbackResponse.ProtoReflect.Descriptor instead.
func (*CreateCallbackResponse) Descriptor() ([]byte, []int) {
	return file_zitadel_oidc_v2beta_oidc_service_proto_rawDescGZIP(), []int{4}
}

func (x *CreateCallbackResponse) GetDetails() *v2beta.Details {
	if x != nil {
		return x.Details
	}
	return nil
}

func (x *CreateCallbackResponse) GetCallbackUrl() string {
	if x != nil {
		return x.CallbackUrl
	}
	return ""
}

var File_zitadel_oidc_v2beta_oidc_service_proto protoreflect.FileDescriptor

var file_zitadel_oidc_v2beta_oidc_service_proto_rawDesc = []byte{
	0x0a, 0x26, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x76,
	0x32, 0x62, 0x65, 0x74, 0x61, 0x2f, 0x6f, 0x69, 0x64, 0x63, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x13, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65,
	0x6c, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x1a, 0x22, 0x7a,
	0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2f, 0x76, 0x32,
	0x62, 0x65, 0x74, 0x61, 0x2f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x2b, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x63, 0x5f, 0x67, 0x65, 0x6e, 0x5f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x76, 0x32,
	0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x27,
	0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x76, 0x32, 0x62,
	0x65, 0x74, 0x61, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70,
	0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67,
	0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e, 0x61, 0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xa7, 0x01, 0x0a, 0x15, 0x47, 0x65, 0x74, 0x41, 0x75, 0x74, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x8d, 0x01, 0x0a, 0x0f, 0x61, 0x75,
	0x74, 0x68, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x65, 0xfa, 0x42, 0x07, 0x72, 0x05, 0x10, 0x01, 0x18, 0xc8, 0x01, 0x92,
	0x41, 0x58, 0x32, 0x3a, 0x49, 0x44, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x41, 0x75,
	0x74, 0x68, 0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2c, 0x20, 0x61, 0x73, 0x20, 0x6f,
	0x62, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x64, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x72, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x20, 0x55, 0x52, 0x4c, 0x2e, 0x4a, 0x14,
	0x22, 0x31, 0x36, 0x33, 0x38, 0x34, 0x30, 0x37, 0x37, 0x36, 0x38, 0x33, 0x35, 0x34, 0x33, 0x32,
	0x37, 0x30, 0x35, 0x22, 0x78, 0xc8, 0x01, 0x80, 0x01, 0x01, 0x52, 0x0d, 0x61, 0x75, 0x74, 0x68,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x22, 0x5d, 0x0a, 0x16, 0x47, 0x65, 0x74,
	0x41, 0x75, 0x74, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x43, 0x0a, 0x0c, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x72, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x7a, 0x69, 0x74, 0x61,
	0x64, 0x65, 0x6c, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x2e,
	0x41, 0x75, 0x74, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x0b, 0x61, 0x75, 0x74,
	0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0xe8, 0x04, 0x0a, 0x15, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x43, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0xf6, 0x01, 0x0a, 0x0f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x72, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0xcd, 0x01, 0xfa,
	0x42, 0x07, 0x72, 0x05, 0x10, 0x01, 0x18, 0xc8, 0x01, 0x92, 0x41, 0xbf, 0x01, 0x1a, 0x3f, 0x68,
	0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x69, 0x64, 0x2e, 0x6e, 0x65,
	0x74, 0x2f, 0x73, 0x70, 0x65, 0x63, 0x73, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x69, 0x64, 0x2d, 0x63,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2d, 0x31, 0x5f, 0x30, 0x2e,
	0x68, 0x74, 0x6d, 0x6c, 0x23, 0x41, 0x75, 0x74, 0x68, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x32, 0x7c,
	0x53, 0x65, 0x74, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x20, 0x77,
	0x68, 0x65, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x6c, 0x6f, 0x77, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65,
	0x64, 0x2e, 0x20, 0x49, 0x74, 0x20, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x73, 0x20, 0x61, 0x20,
	0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x20, 0x55, 0x52, 0x4c, 0x20, 0x74, 0x6f, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2c,
	0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x20,
	0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x20, 0x73, 0x65, 0x74, 0x2e, 0x52, 0x0d, 0x61, 0x75,
	0x74, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x07, 0x73,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x7a,
	0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x76, 0x32, 0x62, 0x65,
	0x74, 0x61, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x48, 0x00, 0x52, 0x07, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x85, 0x02, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e,
	0x6f, 0x69, 0x64, 0x63, 0x2e, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x2e, 0x41, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x42, 0xc3,
	0x01, 0x92, 0x41, 0xbf, 0x01, 0x1a, 0x3f, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x6f,
	0x70, 0x65, 0x6e, 0x69, 0x64, 0x2e, 0x6e, 0x65, 0x74, 0x2f, 0x73, 0x70, 0x65, 0x63, 0x73, 0x2f,
	0x6f, 0x70, 0x65, 0x6e, 0x69, 0x64, 0x2d, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x2d, 0x63,
	0x6f, 0x72, 0x65, 0x2d, 0x31, 0x5f, 0x30, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x23, 0x41, 0x75, 0x74,
	0x68, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x32, 0x7c, 0x53, 0x65, 0x74, 0x20, 0x74, 0x68, 0x69, 0x73,
	0x20, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x6c,
	0x6f, 0x77, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x2e, 0x20, 0x49, 0x74, 0x20, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x73, 0x20, 0x61, 0x20, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b,
	0x20, 0x55, 0x52, 0x4c, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x70, 0x70, 0x6c,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2c, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x74, 0x68,
	0x65, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x20,
	0x73, 0x65, 0x74, 0x2e, 0x48, 0x00, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x42, 0x14, 0x0a,
	0x0d, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x5f, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x03,
	0xf8, 0x42, 0x01, 0x22, 0x8a, 0x02, 0x0a, 0x07, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x9e, 0x01, 0x0a, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x7f, 0xfa, 0x42, 0x07, 0x72, 0x05, 0x10, 0x01, 0x18, 0xc8, 0x01,
	0x92, 0x41, 0x72, 0x32, 0x54, 0x49, 0x44, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2c, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20,
	0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x75, 0x73, 0x65, 0x72, 0x2e, 0x20,
	0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68,
	0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x4a, 0x14, 0x22, 0x31, 0x36, 0x33, 0x38,
	0x34, 0x30, 0x37, 0x37, 0x36, 0x38, 0x33, 0x35, 0x34, 0x33, 0x32, 0x37, 0x30, 0x35, 0x22, 0x78,
	0xc8, 0x01, 0x80, 0x01, 0x01, 0x52, 0x09, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64,
	0x12, 0x5e, 0x0a, 0x0d, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x6f, 0x6b, 0x65,
	0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x39, 0xfa, 0x42, 0x07, 0x72, 0x05, 0x10, 0x01,
	0x18, 0xc8, 0x01, 0x92, 0x41, 0x2c, 0x32, 0x24, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x74, 0x6f,
	0x20, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x20, 0x69, 0x73, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x78, 0xc8, 0x01, 0x80,
	0x01, 0x01, 0x52, 0x0c, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x22, 0xff, 0x03, 0x0a, 0x16, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x43, 0x61, 0x6c, 0x6c, 0x62,
	0x61, 0x63, 0x6b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x38, 0x0a, 0x07, 0x64,
	0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x7a,
	0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x32,
	0x62, 0x65, 0x74, 0x61, 0x2e, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x07, 0x64, 0x65,
	0x74, 0x61, 0x69, 0x6c, 0x73, 0x12, 0xaa, 0x03, 0x0a, 0x0c, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61,
	0x63, 0x6b, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x86, 0x03, 0x92,
	0x41, 0x82, 0x03, 0x32, 0xb0, 0x02, 0x43, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x20, 0x55,
	0x52, 0x4c, 0x20, 0x77, 0x68, 0x65, 0x72, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x75, 0x73, 0x65,
	0x72, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x64, 0x69,
	0x72, 0x65, 0x63, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20,
	0x22, 0x33, 0x30, 0x32, 0x20, 0x46, 0x4f, 0x55, 0x4e, 0x44, 0x22, 0x20, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x2e, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x64, 0x65, 0x74,
	0x61, 0x69, 0x6c, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x70, 0x70,
	0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x6f, 0x62, 0x74, 0x61,
	0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x20, 0x6f, 0x6e,
	0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x2c, 0x20, 0x6f, 0x72, 0x20, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x20, 0x6f, 0x6e, 0x20, 0x66, 0x61,
	0x69, 0x6c, 0x75, 0x72, 0x65, 0x2e, 0x20, 0x4e, 0x6f, 0x74, 0x65, 0x20, 0x74, 0x68, 0x61, 0x74,
	0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x20, 0x6d, 0x75, 0x73, 0x74,
	0x20, 0x62, 0x65, 0x20, 0x74, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x20, 0x61, 0x73, 0x20, 0x63,
	0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2c, 0x20, 0x61, 0x73, 0x20, 0x74,
	0x68, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x64, 0x20, 0x63, 0x6f, 0x64,
	0x65, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6f,
	0x20, 0x6f, 0x62, 0x74, 0x61, 0x69, 0x6e, 0x20, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x20, 0x6f,
	0x6e, 0x20, 0x62, 0x65, 0x68, 0x61, 0x6c, 0x76, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x75, 0x73, 0x65, 0x72, 0x2e, 0x4a, 0x4d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
	0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
	0x6f, 0x72, 0x67, 0x2f, 0x63, 0x62, 0x3f, 0x63, 0x6f, 0x64, 0x65, 0x3d, 0x53, 0x70, 0x6c, 0x78,
	0x6c, 0x4f, 0x42, 0x65, 0x5a, 0x51, 0x51, 0x59, 0x62, 0x59, 0x53, 0x36, 0x57, 0x78, 0x53, 0x62,
	0x49, 0x41, 0x26, 0x73, 0x74, 0x61, 0x74, 0x65, 0x3d, 0x61, 0x66, 0x30, 0x69, 0x66, 0x6a, 0x73,
	0x6c, 0x64, 0x6b, 0x6a, 0x22, 0x52, 0x0b, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x55,
	0x72, 0x6c, 0x32, 0xbd, 0x07, 0x0a, 0x0b, 0x4f, 0x49, 0x44, 0x43, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x12, 0xf1, 0x02, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x41, 0x75, 0x74, 0x68, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2a, 0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e,
	0x6f, 0x69, 0x64, 0x63, 0x2e, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x2e, 0x47, 0x65, 0x74, 0x41,
	0x75, 0x74, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x2b, 0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x6f, 0x69, 0x64, 0x63,
	0x2e, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x2e, 0x47, 0x65, 0x74, 0x41, 0x75, 0x74, 0x68, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x85,
	0x02, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x2e, 0x12, 0x2c, 0x2f, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61,
	0x2f, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x73, 0x2f, 0x7b, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x5f, 0x69, 0x64, 0x7d, 0x8a, 0xb5, 0x18, 0x11, 0x0a, 0x0f, 0x0a, 0x0d, 0x61, 0x75, 0x74,
	0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x92, 0x41, 0xb8, 0x01, 0x12, 0x1d,
	0x47, 0x65, 0x74, 0x20, 0x4f, 0x49, 0x44, 0x43, 0x20, 0x41, 0x75, 0x74, 0x68, 0x20, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x1a, 0x89, 0x01,
	0x47, 0x65, 0x74, 0x20, 0x4f, 0x49, 0x44, 0x43, 0x20, 0x41, 0x75, 0x74, 0x68, 0x20, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x20, 0x62, 0x79,
	0x20, 0x49, 0x44, 0x2c, 0x20, 0x6f, 0x62, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x64, 0x20, 0x66, 0x72,
	0x6f, 0x6d, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x20,
	0x55, 0x52, 0x4c, 0x2e, 0x20, 0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x73, 0x20, 0x64, 0x65, 0x74,
	0x61, 0x69, 0x6c, 0x73, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x72, 0x65, 0x20, 0x70, 0x61,
	0x72, 0x73, 0x65, 0x64, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x70,
	0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x27, 0x73, 0x20, 0x41, 0x75, 0x74, 0x68,
	0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x4a, 0x0b, 0x0a, 0x03, 0x32, 0x30, 0x30,
	0x12, 0x04, 0x0a, 0x02, 0x4f, 0x4b, 0x12, 0xb9, 0x04, 0x0a, 0x0e, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x43, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x12, 0x2a, 0x2e, 0x7a, 0x69, 0x74, 0x61,
	0x64, 0x65, 0x6c, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x2e,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x43, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2b, 0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e,
	0x6f, 0x69, 0x64, 0x63, 0x2e, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x2e, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x43, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0xcd, 0x03, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x31, 0x22, 0x2c, 0x2f, 0x76, 0x32,
	0x62, 0x65, 0x74, 0x61, 0x2f, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x72,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x2f, 0x7b, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x72, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x7d, 0x3a, 0x01, 0x2a, 0x8a, 0xb5, 0x18, 0x11,
	0x0a, 0x0f, 0x0a, 0x0d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x64, 0x92, 0x41, 0xfd, 0x02, 0x12, 0x32, 0x46, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x20,
	0x61, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x20,
	0x61, 0x6e, 0x64, 0x20, 0x67, 0x65, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x61, 0x6c, 0x6c,
	0x62, 0x61, 0x63, 0x6b, 0x20, 0x55, 0x52, 0x4c, 0x2e, 0x1a, 0xb9, 0x02, 0x46, 0x69, 0x6e, 0x61,
	0x6c, 0x69, 0x7a, 0x65, 0x20, 0x61, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x20, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x67, 0x65, 0x74, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x20, 0x55, 0x52, 0x4c, 0x20, 0x66, 0x6f,
	0x72, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x6f, 0x72, 0x20, 0x66, 0x61, 0x69,
	0x6c, 0x75, 0x72, 0x65, 0x2e, 0x20, 0x54, 0x68, 0x65, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x6d,
	0x75, 0x73, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x65,
	0x64, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x55, 0x52, 0x4c, 0x20, 0x69, 0x6e, 0x20,
	0x6f, 0x72, 0x64, 0x65, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x69, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20,
	0x61, 0x62, 0x6f, 0x75, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x20, 0x6f, 0x72, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x2e, 0x20, 0x4f, 0x6e,
	0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x2c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x55, 0x52,
	0x4c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69,
	0x6c, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x6f, 0x62, 0x74, 0x61, 0x69, 0x6e,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x2e, 0x20, 0x54, 0x68, 0x69,
	0x73, 0x20, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x6f, 0x6e, 0x6c,
	0x79, 0x20, 0x62, 0x65, 0x20, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64, 0x20, 0x6f, 0x6e, 0x63, 0x65,
	0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x20, 0x72, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x2e, 0x4a, 0x0b, 0x0a, 0x03, 0x32, 0x30, 0x30, 0x12, 0x04, 0x0a, 0x02,
	0x4f, 0x4b, 0x42, 0xab, 0x08, 0x5a, 0x34, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65,
	0x6c, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x6f, 0x69, 0x64, 0x63, 0x2f,
	0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x3b, 0x6f, 0x69, 0x64, 0x63, 0x92, 0x41, 0xf1, 0x07, 0x12,
	0xcf, 0x02, 0x0a, 0x0c, 0x4f, 0x49, 0x44, 0x43, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x12, 0xc0, 0x01, 0x47, 0x65, 0x74, 0x20, 0x4f, 0x49, 0x44, 0x43, 0x20, 0x41, 0x75, 0x74, 0x68,
	0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73,
	0x20, 0x61, 0x6e, 0x64, 0x20, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x20, 0x63, 0x61, 0x6c, 0x6c,
	0x62, 0x61, 0x63, 0x6b, 0x20, 0x55, 0x52, 0x4c, 0x73, 0x2e, 0x20, 0x54, 0x68, 0x69, 0x73, 0x20,
	0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x69, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x62, 0x65,
	0x74, 0x61, 0x20, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x20, 0x49, 0x74, 0x20, 0x63, 0x61, 0x6e,
	0x20, 0x41, 0x4e, 0x44, 0x20, 0x77, 0x69, 0x6c, 0x6c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x69, 0x6e,
	0x75, 0x65, 0x20, 0x62, 0x72, 0x65, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x6e, 0x74, 0x69,
	0x6c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x70,
	0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x61, 0x6d, 0x65, 0x20,
	0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x20, 0x61, 0x73,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x6f, 0x67,
	0x69, 0x6e, 0x2e, 0x22, 0x2e, 0x0a, 0x07, 0x5a, 0x49, 0x54, 0x41, 0x44, 0x45, 0x4c, 0x12, 0x13,
	0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e,
	0x63, 0x6f, 0x6d, 0x1a, 0x0e, 0x68, 0x69, 0x40, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e,
	0x63, 0x6f, 0x6d, 0x2a, 0x42, 0x0a, 0x0a, 0x41, 0x70, 0x61, 0x63, 0x68, 0x65, 0x20, 0x32, 0x2e,
	0x30, 0x12, 0x34, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x7a, 0x69,
	0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x62, 0x6c, 0x6f, 0x62, 0x2f, 0x6d, 0x61, 0x69, 0x6e, 0x2f,
	0x4c, 0x49, 0x43, 0x45, 0x4e, 0x53, 0x45, 0x32, 0x08, 0x32, 0x2e, 0x30, 0x2d, 0x62, 0x65, 0x74,
	0x61, 0x1a, 0x0e, 0x24, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x2d, 0x44, 0x4f, 0x4d, 0x41, 0x49,
	0x4e, 0x22, 0x01, 0x2f, 0x2a, 0x02, 0x02, 0x01, 0x32, 0x10, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e, 0x32, 0x10, 0x61, 0x70, 0x70, 0x6c,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x32, 0x1a, 0x61, 0x70,
	0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2d, 0x77,
	0x65, 0x62, 0x2b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x3a, 0x10, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e, 0x3a, 0x10, 0x61, 0x70, 0x70, 0x6c,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x3a, 0x1a, 0x61, 0x70,
	0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2d, 0x77,
	0x65, 0x62, 0x2b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x52, 0x6d, 0x0a, 0x03, 0x34, 0x30, 0x33, 0x12,
	0x66, 0x0a, 0x47, 0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x65, 0x64, 0x20, 0x77, 0x68, 0x65, 0x6e,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x64, 0x6f, 0x65, 0x73, 0x20, 0x6e,
	0x6f, 0x74, 0x20, 0x68, 0x61, 0x76, 0x65, 0x20, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x12, 0x1b, 0x0a, 0x19, 0x1a, 0x17,
	0x23, 0x2f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x72, 0x70,
	0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x50, 0x0a, 0x03, 0x34, 0x30, 0x34, 0x12, 0x49,
	0x0a, 0x2a, 0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x65, 0x64, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x64, 0x6f, 0x65,
	0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x2e, 0x12, 0x1b, 0x0a, 0x19,
	0x1a, 0x17, 0x23, 0x2f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x72, 0x70, 0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5a, 0xc2, 0x01, 0x0a, 0xbf, 0x01, 0x0a,
	0x06, 0x4f, 0x41, 0x75, 0x74, 0x68, 0x32, 0x12, 0xb4, 0x01, 0x08, 0x03, 0x28, 0x04, 0x32, 0x21,
	0x24, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x2d, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x2f, 0x6f,
	0x61, 0x75, 0x74, 0x68, 0x2f, 0x76, 0x32, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
	0x65, 0x3a, 0x1d, 0x24, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x2d, 0x44, 0x4f, 0x4d, 0x41, 0x49,
	0x4e, 0x2f, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x76, 0x32, 0x2f, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
	0x42, 0x6c, 0x0a, 0x10, 0x0a, 0x06, 0x6f, 0x70, 0x65, 0x6e, 0x69, 0x64, 0x12, 0x06, 0x6f, 0x70,
	0x65, 0x6e, 0x69, 0x64, 0x0a, 0x58, 0x0a, 0x2a, 0x75, 0x72, 0x6e, 0x3a, 0x7a, 0x69, 0x74, 0x61,
	0x64, 0x65, 0x6c, 0x3a, 0x69, 0x61, 0x6d, 0x3a, 0x6f, 0x72, 0x67, 0x3a, 0x70, 0x72, 0x6f, 0x6a,
	0x65, 0x63, 0x74, 0x3a, 0x69, 0x64, 0x3a, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x3a, 0x61,
	0x75, 0x64, 0x12, 0x2a, 0x75, 0x72, 0x6e, 0x3a, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x3a,
	0x69, 0x61, 0x6d, 0x3a, 0x6f, 0x72, 0x67, 0x3a, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x3a,
	0x69, 0x64, 0x3a, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x3a, 0x61, 0x75, 0x64, 0x62, 0x40,
	0x0a, 0x3e, 0x0a, 0x06, 0x4f, 0x41, 0x75, 0x74, 0x68, 0x32, 0x12, 0x34, 0x0a, 0x06, 0x6f, 0x70,
	0x65, 0x6e, 0x69, 0x64, 0x0a, 0x2a, 0x75, 0x72, 0x6e, 0x3a, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65,
	0x6c, 0x3a, 0x69, 0x61, 0x6d, 0x3a, 0x6f, 0x72, 0x67, 0x3a, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63,
	0x74, 0x3a, 0x69, 0x64, 0x3a, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x3a, 0x61, 0x75, 0x64,
	0x72, 0x3e, 0x0a, 0x22, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x66,
	0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61, 0x62, 0x6f, 0x75, 0x74, 0x20, 0x5a,
	0x49, 0x54, 0x41, 0x44, 0x45, 0x4c, 0x12, 0x18, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
	0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x64, 0x6f, 0x63, 0x73,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_zitadel_oidc_v2beta_oidc_service_proto_rawDescOnce sync.Once
	file_zitadel_oidc_v2beta_oidc_service_proto_rawDescData = file_zitadel_oidc_v2beta_oidc_service_proto_rawDesc
)

func file_zitadel_oidc_v2beta_oidc_service_proto_rawDescGZIP() []byte {
	file_zitadel_oidc_v2beta_oidc_service_proto_rawDescOnce.Do(func() {
		file_zitadel_oidc_v2beta_oidc_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_zitadel_oidc_v2beta_oidc_service_proto_rawDescData)
	})
	return file_zitadel_oidc_v2beta_oidc_service_proto_rawDescData
}

var file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_zitadel_oidc_v2beta_oidc_service_proto_goTypes = []interface{}{
	(*GetAuthRequestRequest)(nil),  // 0: zitadel.oidc.v2beta.GetAuthRequestRequest
	(*GetAuthRequestResponse)(nil), // 1: zitadel.oidc.v2beta.GetAuthRequestResponse
	(*CreateCallbackRequest)(nil),  // 2: zitadel.oidc.v2beta.CreateCallbackRequest
	(*Session)(nil),                // 3: zitadel.oidc.v2beta.Session
	(*CreateCallbackResponse)(nil), // 4: zitadel.oidc.v2beta.CreateCallbackResponse
	(*AuthRequest)(nil),            // 5: zitadel.oidc.v2beta.AuthRequest
	(*AuthorizationError)(nil),     // 6: zitadel.oidc.v2beta.AuthorizationError
	(*v2beta.Details)(nil),         // 7: zitadel.object.v2beta.Details
}
var file_zitadel_oidc_v2beta_oidc_service_proto_depIdxs = []int32{
	5, // 0: zitadel.oidc.v2beta.GetAuthRequestResponse.auth_request:type_name -> zitadel.oidc.v2beta.AuthRequest
	3, // 1: zitadel.oidc.v2beta.CreateCallbackRequest.session:type_name -> zitadel.oidc.v2beta.Session
	6, // 2: zitadel.oidc.v2beta.CreateCallbackRequest.error:type_name -> zitadel.oidc.v2beta.AuthorizationError
	7, // 3: zitadel.oidc.v2beta.CreateCallbackResponse.details:type_name -> zitadel.object.v2beta.Details
	0, // 4: zitadel.oidc.v2beta.OIDCService.GetAuthRequest:input_type -> zitadel.oidc.v2beta.GetAuthRequestRequest
	2, // 5: zitadel.oidc.v2beta.OIDCService.CreateCallback:input_type -> zitadel.oidc.v2beta.CreateCallbackRequest
	1, // 6: zitadel.oidc.v2beta.OIDCService.GetAuthRequest:output_type -> zitadel.oidc.v2beta.GetAuthRequestResponse
	4, // 7: zitadel.oidc.v2beta.OIDCService.CreateCallback:output_type -> zitadel.oidc.v2beta.CreateCallbackResponse
	6, // [6:8] is the sub-list for method output_type
	4, // [4:6] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_zitadel_oidc_v2beta_oidc_service_proto_init() }
func file_zitadel_oidc_v2beta_oidc_service_proto_init() {
	if File_zitadel_oidc_v2beta_oidc_service_proto != nil {
		return
	}
	file_zitadel_oidc_v2beta_authorization_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAuthRequestRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAuthRequestResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateCallbackRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Session); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateCallbackResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*CreateCallbackRequest_Session)(nil),
		(*CreateCallbackRequest_Error)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_zitadel_oidc_v2beta_oidc_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_zitadel_oidc_v2beta_oidc_service_proto_goTypes,
		DependencyIndexes: file_zitadel_oidc_v2beta_oidc_service_proto_depIdxs,
		MessageInfos:      file_zitadel_oidc_v2beta_oidc_service_proto_msgTypes,
	}.Build()
	File_zitadel_oidc_v2beta_oidc_service_proto = out.File
	file_zitadel_oidc_v2beta_oidc_service_proto_rawDesc = nil
	file_zitadel_oidc_v2beta_oidc_service_proto_goTypes = nil
	file_zitadel_oidc_v2beta_oidc_service_proto_depIdxs = nil
}

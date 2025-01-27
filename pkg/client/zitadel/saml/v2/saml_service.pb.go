// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.25.1
// source: zitadel/saml/v2/saml_service.proto

package saml

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	v2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
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

type GetSAMLRequestRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the SAML Request, as obtained from the redirect URL.
	SamlRequestId string `protobuf:"bytes,1,opt,name=saml_request_id,json=samlRequestId,proto3" json:"saml_request_id,omitempty"`
}

func (x *GetSAMLRequestRequest) Reset() {
	*x = GetSAMLRequestRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetSAMLRequestRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSAMLRequestRequest) ProtoMessage() {}

func (x *GetSAMLRequestRequest) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSAMLRequestRequest.ProtoReflect.Descriptor instead.
func (*GetSAMLRequestRequest) Descriptor() ([]byte, []int) {
	return file_zitadel_saml_v2_saml_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetSAMLRequestRequest) GetSamlRequestId() string {
	if x != nil {
		return x.SamlRequestId
	}
	return ""
}

type GetSAMLRequestResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SamlRequest *SAMLRequest `protobuf:"bytes,1,opt,name=saml_request,json=samlRequest,proto3" json:"saml_request,omitempty"`
}

func (x *GetSAMLRequestResponse) Reset() {
	*x = GetSAMLRequestResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetSAMLRequestResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSAMLRequestResponse) ProtoMessage() {}

func (x *GetSAMLRequestResponse) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSAMLRequestResponse.ProtoReflect.Descriptor instead.
func (*GetSAMLRequestResponse) Descriptor() ([]byte, []int) {
	return file_zitadel_saml_v2_saml_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetSAMLRequestResponse) GetSamlRequest() *SAMLRequest {
	if x != nil {
		return x.SamlRequest
	}
	return nil
}

type CreateResponseRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the SAML Request.
	SamlRequestId string `protobuf:"bytes,1,opt,name=saml_request_id,json=samlRequestId,proto3" json:"saml_request_id,omitempty"`
	// Types that are assignable to ResponseKind:
	//
	//	*CreateResponseRequest_Session
	//	*CreateResponseRequest_Error
	ResponseKind isCreateResponseRequest_ResponseKind `protobuf_oneof:"response_kind"`
}

func (x *CreateResponseRequest) Reset() {
	*x = CreateResponseRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateResponseRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateResponseRequest) ProtoMessage() {}

func (x *CreateResponseRequest) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateResponseRequest.ProtoReflect.Descriptor instead.
func (*CreateResponseRequest) Descriptor() ([]byte, []int) {
	return file_zitadel_saml_v2_saml_service_proto_rawDescGZIP(), []int{2}
}

func (x *CreateResponseRequest) GetSamlRequestId() string {
	if x != nil {
		return x.SamlRequestId
	}
	return ""
}

func (m *CreateResponseRequest) GetResponseKind() isCreateResponseRequest_ResponseKind {
	if m != nil {
		return m.ResponseKind
	}
	return nil
}

func (x *CreateResponseRequest) GetSession() *Session {
	if x, ok := x.GetResponseKind().(*CreateResponseRequest_Session); ok {
		return x.Session
	}
	return nil
}

func (x *CreateResponseRequest) GetError() *AuthorizationError {
	if x, ok := x.GetResponseKind().(*CreateResponseRequest_Error); ok {
		return x.Error
	}
	return nil
}

type isCreateResponseRequest_ResponseKind interface {
	isCreateResponseRequest_ResponseKind()
}

type CreateResponseRequest_Session struct {
	Session *Session `protobuf:"bytes,2,opt,name=session,proto3,oneof"`
}

type CreateResponseRequest_Error struct {
	// Set this field when the authorization flow failed. It creates a response depending on the SP, with the error details set.
	Error *AuthorizationError `protobuf:"bytes,3,opt,name=error,proto3,oneof"`
}

func (*CreateResponseRequest_Session) isCreateResponseRequest_ResponseKind() {}

func (*CreateResponseRequest_Error) isCreateResponseRequest_ResponseKind() {}

type Session struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the session, used to login the user. Connects the session to the SAML Request.
	SessionId string `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	// Token to verify the session is valid.
	SessionToken string `protobuf:"bytes,2,opt,name=session_token,json=sessionToken,proto3" json:"session_token,omitempty"`
}

func (x *Session) Reset() {
	*x = Session{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Session) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Session) ProtoMessage() {}

func (x *Session) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[3]
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
	return file_zitadel_saml_v2_saml_service_proto_rawDescGZIP(), []int{3}
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

type CreateResponseResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Details *v2.Details `protobuf:"bytes,1,opt,name=details,proto3" json:"details,omitempty"`
	// URL including the Assertion Consumer Service where the user should be redirected or has to call per POST, depending on the binding. Contains details for the application to obtain the response on success, or error details on failure. Note that this field must be treated as credentials, as the contained SAMLResponse or code can be used on behalve of the user.
	Url string `protobuf:"bytes,2,opt,name=url,proto3" json:"url,omitempty"`
	// Binding is defined through the request, what the IDP is able to use and what bindings are available for the SP.
	//
	// Types that are assignable to Binding:
	//
	//	*CreateResponseResponse_Redirect
	//	*CreateResponseResponse_Post
	Binding isCreateResponseResponse_Binding `protobuf_oneof:"binding"`
}

func (x *CreateResponseResponse) Reset() {
	*x = CreateResponseResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateResponseResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateResponseResponse) ProtoMessage() {}

func (x *CreateResponseResponse) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateResponseResponse.ProtoReflect.Descriptor instead.
func (*CreateResponseResponse) Descriptor() ([]byte, []int) {
	return file_zitadel_saml_v2_saml_service_proto_rawDescGZIP(), []int{4}
}

func (x *CreateResponseResponse) GetDetails() *v2.Details {
	if x != nil {
		return x.Details
	}
	return nil
}

func (x *CreateResponseResponse) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (m *CreateResponseResponse) GetBinding() isCreateResponseResponse_Binding {
	if m != nil {
		return m.Binding
	}
	return nil
}

func (x *CreateResponseResponse) GetRedirect() *RedirectResponse {
	if x, ok := x.GetBinding().(*CreateResponseResponse_Redirect); ok {
		return x.Redirect
	}
	return nil
}

func (x *CreateResponseResponse) GetPost() *PostResponse {
	if x, ok := x.GetBinding().(*CreateResponseResponse_Post); ok {
		return x.Post
	}
	return nil
}

type isCreateResponseResponse_Binding interface {
	isCreateResponseResponse_Binding()
}

type CreateResponseResponse_Redirect struct {
	// Set if the binding is Redirect-Binding, where the user can directly be redirected to the application, using a \"302 FOUND\" status to the URL.
	Redirect *RedirectResponse `protobuf:"bytes,3,opt,name=redirect,proto3,oneof"`
}

type CreateResponseResponse_Post struct {
	// Set if the binding is POST-Binding, where the application expects to be called per HTTP POST with the SAMLResponse and RelayState in the form body.
	Post *PostResponse `protobuf:"bytes,4,opt,name=post,proto3,oneof"`
}

func (*CreateResponseResponse_Redirect) isCreateResponseResponse_Binding() {}

func (*CreateResponseResponse_Post) isCreateResponseResponse_Binding() {}

type RedirectResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RedirectResponse) Reset() {
	*x = RedirectResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RedirectResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RedirectResponse) ProtoMessage() {}

func (x *RedirectResponse) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RedirectResponse.ProtoReflect.Descriptor instead.
func (*RedirectResponse) Descriptor() ([]byte, []int) {
	return file_zitadel_saml_v2_saml_service_proto_rawDescGZIP(), []int{5}
}

type PostResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RelayState   string `protobuf:"bytes,1,opt,name=relay_state,json=relayState,proto3" json:"relay_state,omitempty"`
	SamlResponse string `protobuf:"bytes,2,opt,name=saml_response,json=samlResponse,proto3" json:"saml_response,omitempty"`
}

func (x *PostResponse) Reset() {
	*x = PostResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PostResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PostResponse) ProtoMessage() {}

func (x *PostResponse) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_saml_v2_saml_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PostResponse.ProtoReflect.Descriptor instead.
func (*PostResponse) Descriptor() ([]byte, []int) {
	return file_zitadel_saml_v2_saml_service_proto_rawDescGZIP(), []int{6}
}

func (x *PostResponse) GetRelayState() string {
	if x != nil {
		return x.RelayState
	}
	return ""
}

func (x *PostResponse) GetSamlResponse() string {
	if x != nil {
		return x.SamlResponse
	}
	return ""
}

var File_zitadel_saml_v2_saml_service_proto protoreflect.FileDescriptor

var file_zitadel_saml_v2_saml_service_proto_rawDesc = []byte{
	0x0a, 0x22, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x73, 0x61, 0x6d, 0x6c, 0x2f, 0x76,
	0x32, 0x2f, 0x73, 0x61, 0x6d, 0x6c, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x61,
	0x6d, 0x6c, 0x2e, 0x76, 0x32, 0x1a, 0x1e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x6f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x2f, 0x76, 0x32, 0x2f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2b, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x5f, 0x67, 0x65, 0x6e, 0x5f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65,
	0x6c, 0x2f, 0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x23, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x73, 0x61, 0x6d, 0x6c,
	0x2f, 0x76, 0x32, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70,
	0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67,
	0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e, 0x61, 0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x6a, 0x0a, 0x15, 0x47, 0x65, 0x74, 0x53, 0x41, 0x4d, 0x4c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x51, 0x0a, 0x0f, 0x73, 0x61, 0x6d, 0x6c,
	0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x29, 0x92, 0x41, 0x1c, 0x4a, 0x14, 0x22, 0x31, 0x36, 0x33, 0x38, 0x34, 0x30, 0x37,
	0x37, 0x36, 0x38, 0x33, 0x35, 0x34, 0x33, 0x32, 0x37, 0x30, 0x35, 0x22, 0x78, 0xc8, 0x01, 0x80,
	0x01, 0x01, 0xfa, 0x42, 0x07, 0x72, 0x05, 0x10, 0x01, 0x18, 0xc8, 0x01, 0x52, 0x0d, 0x73, 0x61,
	0x6d, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x22, 0x59, 0x0a, 0x16, 0x47,
	0x65, 0x74, 0x53, 0x41, 0x4d, 0x4c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3f, 0x0a, 0x0c, 0x73, 0x61, 0x6d, 0x6c, 0x5f, 0x72, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x7a, 0x69,
	0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x61, 0x6d, 0x6c, 0x2e, 0x76, 0x32, 0x2e, 0x53, 0x41,
	0x4d, 0x4c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x0b, 0x73, 0x61, 0x6d, 0x6c, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0xed, 0x01, 0x0a, 0x15, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x4b, 0x0a, 0x0f, 0x73, 0x61, 0x6d, 0x6c, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x23, 0x92, 0x41, 0x16, 0x4a, 0x14,
	0x22, 0x31, 0x36, 0x33, 0x38, 0x34, 0x30, 0x37, 0x37, 0x36, 0x38, 0x33, 0x35, 0x34, 0x33, 0x32,
	0x37, 0x30, 0x35, 0x22, 0xfa, 0x42, 0x07, 0x72, 0x05, 0x10, 0x01, 0x18, 0xc8, 0x01, 0x52, 0x0d,
	0x73, 0x61, 0x6d, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x34, 0x0a,
	0x07, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18,
	0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x61, 0x6d, 0x6c, 0x2e, 0x76, 0x32,
	0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x48, 0x00, 0x52, 0x07, 0x73, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x12, 0x3b, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x23, 0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x61, 0x6d,
	0x6c, 0x2e, 0x76, 0x32, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x48, 0x00, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72,
	0x42, 0x14, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x6b, 0x69, 0x6e,
	0x64, 0x12, 0x03, 0xf8, 0x42, 0x01, 0x22, 0x8d, 0x01, 0x0a, 0x07, 0x53, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x12, 0x48, 0x0a, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x29, 0x92, 0x41, 0x1c, 0x4a, 0x14, 0x22, 0x31, 0x36,
	0x33, 0x38, 0x34, 0x30, 0x37, 0x37, 0x36, 0x38, 0x33, 0x35, 0x34, 0x33, 0x32, 0x37, 0x30, 0x35,
	0x22, 0x78, 0xc8, 0x01, 0x80, 0x01, 0x01, 0xfa, 0x42, 0x07, 0x72, 0x05, 0x10, 0x01, 0x18, 0xc8,
	0x01, 0x52, 0x09, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x0d,
	0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x13, 0x92, 0x41, 0x06, 0x78, 0xc8, 0x01, 0x80, 0x01, 0x01, 0xfa, 0x42,
	0x07, 0x72, 0x05, 0x10, 0x01, 0x18, 0xc8, 0x01, 0x52, 0x0c, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x87, 0x02, 0x0a, 0x16, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x34, 0x0a, 0x07, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x2e, 0x76, 0x32, 0x2e, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x07,
	0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x36, 0x0a, 0x03, 0x75, 0x72, 0x6c, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x24, 0x92, 0x41, 0x21, 0x4a, 0x1f, 0x22, 0x68, 0x74, 0x74, 0x70,
	0x73, 0x3a, 0x2f, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
	0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x63, 0x62, 0x22, 0x52, 0x03, 0x75, 0x72, 0x6c, 0x12,
	0x3f, 0x0a, 0x08, 0x72, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x21, 0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x61, 0x6d, 0x6c,
	0x2e, 0x76, 0x32, 0x2e, 0x52, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x48, 0x00, 0x52, 0x08, 0x72, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74,
	0x12, 0x33, 0x0a, 0x04, 0x70, 0x6f, 0x73, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d,
	0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x61, 0x6d, 0x6c, 0x2e, 0x76, 0x32,
	0x2e, 0x50, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x48, 0x00, 0x52,
	0x04, 0x70, 0x6f, 0x73, 0x74, 0x42, 0x09, 0x0a, 0x07, 0x62, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67,
	0x22, 0x12, 0x0a, 0x10, 0x52, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x54, 0x0a, 0x0c, 0x50, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x5f, 0x73, 0x74,
	0x61, 0x74, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x72, 0x65, 0x6c, 0x61, 0x79,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x61, 0x6d, 0x6c, 0x5f, 0x72, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x73, 0x61,
	0x6d, 0x6c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0x8e, 0x07, 0x0a, 0x0b, 0x53,
	0x41, 0x4d, 0x4c, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0xba, 0x02, 0x0a, 0x0e, 0x47,
	0x65, 0x74, 0x53, 0x41, 0x4d, 0x4c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x26, 0x2e,
	0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x61, 0x6d, 0x6c, 0x2e, 0x76, 0x32, 0x2e,
	0x47, 0x65, 0x74, 0x53, 0x41, 0x4d, 0x4c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x27, 0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e,
	0x73, 0x61, 0x6d, 0x6c, 0x2e, 0x76, 0x32, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x41, 0x4d, 0x4c, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0xd6,
	0x01, 0x92, 0x41, 0x8d, 0x01, 0x12, 0x18, 0x47, 0x65, 0x74, 0x20, 0x53, 0x41, 0x4d, 0x4c, 0x20,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x1a,
	0x64, 0x47, 0x65, 0x74, 0x20, 0x53, 0x41, 0x4d, 0x4c, 0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x20, 0x62, 0x79, 0x20, 0x49, 0x44, 0x2e,
	0x20, 0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x73, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73,
	0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x72, 0x65, 0x20, 0x70, 0x61, 0x72, 0x73, 0x65, 0x64,
	0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x27, 0x73, 0x20, 0x53, 0x41, 0x4d, 0x4c, 0x20, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x2e, 0x4a, 0x0b, 0x0a, 0x03, 0x32, 0x30, 0x30, 0x12, 0x04, 0x0a, 0x02,
	0x4f, 0x4b, 0x8a, 0xb5, 0x18, 0x11, 0x0a, 0x0f, 0x0a, 0x0d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e,
	0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x2a, 0x12, 0x28, 0x2f,
	0x76, 0x32, 0x2f, 0x73, 0x61, 0x6d, 0x6c, 0x2f, 0x73, 0x61, 0x6d, 0x6c, 0x5f, 0x72, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x73, 0x2f, 0x7b, 0x73, 0x61, 0x6d, 0x6c, 0x5f, 0x72, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x7d, 0x12, 0xc1, 0x04, 0x0a, 0x0e, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x26, 0x2e, 0x7a, 0x69, 0x74,
	0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x61, 0x6d, 0x6c, 0x2e, 0x76, 0x32, 0x2e, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x27, 0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x73, 0x61, 0x6d,
	0x6c, 0x2e, 0x76, 0x32, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0xdd, 0x03, 0x92, 0x41,
	0x91, 0x03, 0x12, 0x2d, 0x46, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x20, 0x61, 0x20, 0x53,
	0x41, 0x4d, 0x4c, 0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x20, 0x61, 0x6e, 0x64, 0x20,
	0x67, 0x65, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x2e, 0x1a, 0xd2, 0x02, 0x46, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x20, 0x61, 0x20, 0x53,
	0x41, 0x4d, 0x4c, 0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x20, 0x61, 0x6e, 0x64, 0x20,
	0x67, 0x65, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x20, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x6f, 0x72, 0x20,
	0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x6f, 0x72, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x75,
	0x72, 0x65, 0x2e, 0x20, 0x54, 0x68, 0x65, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x64,
	0x20, 0x61, 0x73, 0x20, 0x70, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x53, 0x41, 0x4d, 0x4c,
	0x20, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x69,
	0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61, 0x62, 0x6f, 0x75, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x6f, 0x72, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x75,
	0x72, 0x65, 0x2e, 0x20, 0x4f, 0x6e, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x2c, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x20, 0x63, 0x6f, 0x6e,
	0x74, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x20, 0x66, 0x6f,
	0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x20, 0x74, 0x6f, 0x20, 0x6f, 0x62, 0x74, 0x61, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x53, 0x41, 0x4d, 0x4c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x20, 0x54, 0x68,
	0x69, 0x73, 0x20, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x6f, 0x6e,
	0x6c, 0x79, 0x20, 0x62, 0x65, 0x20, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64, 0x20, 0x6f, 0x6e, 0x63,
	0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x6e, 0x20, 0x53, 0x41, 0x4d, 0x4c, 0x20, 0x72, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x4a, 0x0b, 0x0a, 0x03, 0x32, 0x30, 0x30, 0x12, 0x04, 0x0a,
	0x02, 0x4f, 0x4b, 0x8a, 0xb5, 0x18, 0x11, 0x0a, 0x0f, 0x0a, 0x0d, 0x61, 0x75, 0x74, 0x68, 0x65,
	0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x2d, 0x3a, 0x01,
	0x2a, 0x22, 0x28, 0x2f, 0x76, 0x32, 0x2f, 0x73, 0x61, 0x6d, 0x6c, 0x2f, 0x73, 0x61, 0x6d, 0x6c,
	0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x2f, 0x7b, 0x73, 0x61, 0x6d, 0x6c, 0x5f,
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x7d, 0x42, 0x98, 0x07, 0x92, 0x41,
	0xe2, 0x06, 0x12, 0xc0, 0x01, 0x0a, 0x0c, 0x53, 0x41, 0x4d, 0x4c, 0x20, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x12, 0x37, 0x47, 0x65, 0x74, 0x20, 0x53, 0x41, 0x4d, 0x4c, 0x20, 0x41, 0x75,
	0x74, 0x68, 0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x20, 0x64, 0x65, 0x74, 0x61, 0x69,
	0x6c, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x20, 0x63, 0x61,
	0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x20, 0x55, 0x52, 0x4c, 0x73, 0x2e, 0x22, 0x2e, 0x0a, 0x07,
	0x5a, 0x49, 0x54, 0x41, 0x44, 0x45, 0x4c, 0x12, 0x13, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
	0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x1a, 0x0e, 0x68, 0x69,
	0x40, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x2a, 0x42, 0x0a, 0x0a,
	0x41, 0x70, 0x61, 0x63, 0x68, 0x65, 0x20, 0x32, 0x2e, 0x30, 0x12, 0x34, 0x68, 0x74, 0x74, 0x70,
	0x73, 0x3a, 0x2f, 0x2f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x7a,
	0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x62,
	0x6c, 0x6f, 0x62, 0x2f, 0x6d, 0x61, 0x69, 0x6e, 0x2f, 0x4c, 0x49, 0x43, 0x45, 0x4e, 0x53, 0x45,
	0x32, 0x03, 0x32, 0x2e, 0x30, 0x1a, 0x0e, 0x24, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x2d, 0x44,
	0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x22, 0x01, 0x2f, 0x2a, 0x02, 0x02, 0x01, 0x32, 0x10, 0x61, 0x70,
	0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e, 0x32, 0x10,
	0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72, 0x70, 0x63,
	0x32, 0x1a, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72,
	0x70, 0x63, 0x2d, 0x77, 0x65, 0x62, 0x2b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x3a, 0x10, 0x61, 0x70,
	0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e, 0x3a, 0x10,
	0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72, 0x70, 0x63,
	0x3a, 0x1a, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72,
	0x70, 0x63, 0x2d, 0x77, 0x65, 0x62, 0x2b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x52, 0x6d, 0x0a, 0x03,
	0x34, 0x30, 0x33, 0x12, 0x66, 0x0a, 0x47, 0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x65, 0x64, 0x20,
	0x77, 0x68, 0x65, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x64, 0x6f,
	0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x68, 0x61, 0x76, 0x65, 0x20, 0x70, 0x65, 0x72, 0x6d,
	0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x12, 0x1b,
	0x0a, 0x19, 0x1a, 0x17, 0x23, 0x2f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x72, 0x70, 0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x50, 0x0a, 0x03, 0x34,
	0x30, 0x34, 0x12, 0x49, 0x0a, 0x2a, 0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x65, 0x64, 0x20, 0x77,
	0x68, 0x65, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x20, 0x64, 0x6f, 0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x2e,
	0x12, 0x1b, 0x0a, 0x19, 0x1a, 0x17, 0x23, 0x2f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2f, 0x72, 0x70, 0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5a, 0xc2, 0x01,
	0x0a, 0xbf, 0x01, 0x0a, 0x06, 0x4f, 0x41, 0x75, 0x74, 0x68, 0x32, 0x12, 0xb4, 0x01, 0x08, 0x03,
	0x28, 0x04, 0x32, 0x21, 0x24, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x2d, 0x44, 0x4f, 0x4d, 0x41,
	0x49, 0x4e, 0x2f, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x76, 0x32, 0x2f, 0x61, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x3a, 0x1d, 0x24, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x2d, 0x44,
	0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x2f, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x76, 0x32, 0x2f, 0x74,
	0x6f, 0x6b, 0x65, 0x6e, 0x42, 0x6c, 0x0a, 0x10, 0x0a, 0x06, 0x6f, 0x70, 0x65, 0x6e, 0x69, 0x64,
	0x12, 0x06, 0x6f, 0x70, 0x65, 0x6e, 0x69, 0x64, 0x0a, 0x58, 0x0a, 0x2a, 0x75, 0x72, 0x6e, 0x3a,
	0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x3a, 0x69, 0x61, 0x6d, 0x3a, 0x6f, 0x72, 0x67, 0x3a,
	0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x69, 0x64, 0x3a, 0x7a, 0x69, 0x74, 0x61, 0x64,
	0x65, 0x6c, 0x3a, 0x61, 0x75, 0x64, 0x12, 0x2a, 0x75, 0x72, 0x6e, 0x3a, 0x7a, 0x69, 0x74, 0x61,
	0x64, 0x65, 0x6c, 0x3a, 0x69, 0x61, 0x6d, 0x3a, 0x6f, 0x72, 0x67, 0x3a, 0x70, 0x72, 0x6f, 0x6a,
	0x65, 0x63, 0x74, 0x3a, 0x69, 0x64, 0x3a, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x3a, 0x61,
	0x75, 0x64, 0x62, 0x40, 0x0a, 0x3e, 0x0a, 0x06, 0x4f, 0x41, 0x75, 0x74, 0x68, 0x32, 0x12, 0x34,
	0x0a, 0x06, 0x6f, 0x70, 0x65, 0x6e, 0x69, 0x64, 0x0a, 0x2a, 0x75, 0x72, 0x6e, 0x3a, 0x7a, 0x69,
	0x74, 0x61, 0x64, 0x65, 0x6c, 0x3a, 0x69, 0x61, 0x6d, 0x3a, 0x6f, 0x72, 0x67, 0x3a, 0x70, 0x72,
	0x6f, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x69, 0x64, 0x3a, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c,
	0x3a, 0x61, 0x75, 0x64, 0x72, 0x3e, 0x0a, 0x22, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x65, 0x64,
	0x20, 0x69, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61, 0x62, 0x6f,
	0x75, 0x74, 0x20, 0x5a, 0x49, 0x54, 0x41, 0x44, 0x45, 0x4c, 0x12, 0x18, 0x68, 0x74, 0x74, 0x70,
	0x73, 0x3a, 0x2f, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x64, 0x6f, 0x63, 0x73, 0x5a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c,
	0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x73, 0x61, 0x6d, 0x6c, 0x2f, 0x76,
	0x32, 0x3b, 0x73, 0x61, 0x6d, 0x6c, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_zitadel_saml_v2_saml_service_proto_rawDescOnce sync.Once
	file_zitadel_saml_v2_saml_service_proto_rawDescData = file_zitadel_saml_v2_saml_service_proto_rawDesc
)

func file_zitadel_saml_v2_saml_service_proto_rawDescGZIP() []byte {
	file_zitadel_saml_v2_saml_service_proto_rawDescOnce.Do(func() {
		file_zitadel_saml_v2_saml_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_zitadel_saml_v2_saml_service_proto_rawDescData)
	})
	return file_zitadel_saml_v2_saml_service_proto_rawDescData
}

var file_zitadel_saml_v2_saml_service_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_zitadel_saml_v2_saml_service_proto_goTypes = []interface{}{
	(*GetSAMLRequestRequest)(nil),  // 0: zitadel.saml.v2.GetSAMLRequestRequest
	(*GetSAMLRequestResponse)(nil), // 1: zitadel.saml.v2.GetSAMLRequestResponse
	(*CreateResponseRequest)(nil),  // 2: zitadel.saml.v2.CreateResponseRequest
	(*Session)(nil),                // 3: zitadel.saml.v2.Session
	(*CreateResponseResponse)(nil), // 4: zitadel.saml.v2.CreateResponseResponse
	(*RedirectResponse)(nil),       // 5: zitadel.saml.v2.RedirectResponse
	(*PostResponse)(nil),           // 6: zitadel.saml.v2.PostResponse
	(*SAMLRequest)(nil),            // 7: zitadel.saml.v2.SAMLRequest
	(*AuthorizationError)(nil),     // 8: zitadel.saml.v2.AuthorizationError
	(*v2.Details)(nil),             // 9: zitadel.object.v2.Details
}
var file_zitadel_saml_v2_saml_service_proto_depIdxs = []int32{
	7, // 0: zitadel.saml.v2.GetSAMLRequestResponse.saml_request:type_name -> zitadel.saml.v2.SAMLRequest
	3, // 1: zitadel.saml.v2.CreateResponseRequest.session:type_name -> zitadel.saml.v2.Session
	8, // 2: zitadel.saml.v2.CreateResponseRequest.error:type_name -> zitadel.saml.v2.AuthorizationError
	9, // 3: zitadel.saml.v2.CreateResponseResponse.details:type_name -> zitadel.object.v2.Details
	5, // 4: zitadel.saml.v2.CreateResponseResponse.redirect:type_name -> zitadel.saml.v2.RedirectResponse
	6, // 5: zitadel.saml.v2.CreateResponseResponse.post:type_name -> zitadel.saml.v2.PostResponse
	0, // 6: zitadel.saml.v2.SAMLService.GetSAMLRequest:input_type -> zitadel.saml.v2.GetSAMLRequestRequest
	2, // 7: zitadel.saml.v2.SAMLService.CreateResponse:input_type -> zitadel.saml.v2.CreateResponseRequest
	1, // 8: zitadel.saml.v2.SAMLService.GetSAMLRequest:output_type -> zitadel.saml.v2.GetSAMLRequestResponse
	4, // 9: zitadel.saml.v2.SAMLService.CreateResponse:output_type -> zitadel.saml.v2.CreateResponseResponse
	8, // [8:10] is the sub-list for method output_type
	6, // [6:8] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_zitadel_saml_v2_saml_service_proto_init() }
func file_zitadel_saml_v2_saml_service_proto_init() {
	if File_zitadel_saml_v2_saml_service_proto != nil {
		return
	}
	file_zitadel_saml_v2_authorization_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_zitadel_saml_v2_saml_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetSAMLRequestRequest); i {
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
		file_zitadel_saml_v2_saml_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetSAMLRequestResponse); i {
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
		file_zitadel_saml_v2_saml_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateResponseRequest); i {
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
		file_zitadel_saml_v2_saml_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
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
		file_zitadel_saml_v2_saml_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateResponseResponse); i {
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
		file_zitadel_saml_v2_saml_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RedirectResponse); i {
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
		file_zitadel_saml_v2_saml_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PostResponse); i {
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
	file_zitadel_saml_v2_saml_service_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*CreateResponseRequest_Session)(nil),
		(*CreateResponseRequest_Error)(nil),
	}
	file_zitadel_saml_v2_saml_service_proto_msgTypes[4].OneofWrappers = []interface{}{
		(*CreateResponseResponse_Redirect)(nil),
		(*CreateResponseResponse_Post)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_zitadel_saml_v2_saml_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_zitadel_saml_v2_saml_service_proto_goTypes,
		DependencyIndexes: file_zitadel_saml_v2_saml_service_proto_depIdxs,
		MessageInfos:      file_zitadel_saml_v2_saml_service_proto_msgTypes,
	}.Build()
	File_zitadel_saml_v2_saml_service_proto = out.File
	file_zitadel_saml_v2_saml_service_proto_rawDesc = nil
	file_zitadel_saml_v2_saml_service_proto_goTypes = nil
	file_zitadel_saml_v2_saml_service_proto_depIdxs = nil
}
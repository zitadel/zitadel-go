// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.18.0
// source: zitadel/object/v2beta/object.proto

package object

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Organisation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Org:
	//
	//	*Organisation_OrgId
	//	*Organisation_OrgDomain
	Org isOrganisation_Org `protobuf_oneof:"org"`
}

func (x *Organisation) Reset() {
	*x = Organisation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_object_v2beta_object_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Organisation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Organisation) ProtoMessage() {}

func (x *Organisation) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_object_v2beta_object_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Organisation.ProtoReflect.Descriptor instead.
func (*Organisation) Descriptor() ([]byte, []int) {
	return file_zitadel_object_v2beta_object_proto_rawDescGZIP(), []int{0}
}

func (m *Organisation) GetOrg() isOrganisation_Org {
	if m != nil {
		return m.Org
	}
	return nil
}

func (x *Organisation) GetOrgId() string {
	if x, ok := x.GetOrg().(*Organisation_OrgId); ok {
		return x.OrgId
	}
	return ""
}

func (x *Organisation) GetOrgDomain() string {
	if x, ok := x.GetOrg().(*Organisation_OrgDomain); ok {
		return x.OrgDomain
	}
	return ""
}

type isOrganisation_Org interface {
	isOrganisation_Org()
}

type Organisation_OrgId struct {
	OrgId string `protobuf:"bytes,1,opt,name=org_id,json=orgId,proto3,oneof"`
}

type Organisation_OrgDomain struct {
	OrgDomain string `protobuf:"bytes,2,opt,name=org_domain,json=orgDomain,proto3,oneof"`
}

func (*Organisation_OrgId) isOrganisation_Org() {}

func (*Organisation_OrgDomain) isOrganisation_Org() {}

type RequestContext struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to ResourceOwner:
	//
	//	*RequestContext_OrgId
	//	*RequestContext_Instance
	ResourceOwner isRequestContext_ResourceOwner `protobuf_oneof:"resource_owner"`
}

func (x *RequestContext) Reset() {
	*x = RequestContext{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_object_v2beta_object_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RequestContext) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RequestContext) ProtoMessage() {}

func (x *RequestContext) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_object_v2beta_object_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RequestContext.ProtoReflect.Descriptor instead.
func (*RequestContext) Descriptor() ([]byte, []int) {
	return file_zitadel_object_v2beta_object_proto_rawDescGZIP(), []int{1}
}

func (m *RequestContext) GetResourceOwner() isRequestContext_ResourceOwner {
	if m != nil {
		return m.ResourceOwner
	}
	return nil
}

func (x *RequestContext) GetOrgId() string {
	if x, ok := x.GetResourceOwner().(*RequestContext_OrgId); ok {
		return x.OrgId
	}
	return ""
}

func (x *RequestContext) GetInstance() bool {
	if x, ok := x.GetResourceOwner().(*RequestContext_Instance); ok {
		return x.Instance
	}
	return false
}

type isRequestContext_ResourceOwner interface {
	isRequestContext_ResourceOwner()
}

type RequestContext_OrgId struct {
	OrgId string `protobuf:"bytes,1,opt,name=org_id,json=orgId,proto3,oneof"`
}

type RequestContext_Instance struct {
	Instance bool `protobuf:"varint,2,opt,name=instance,proto3,oneof"`
}

func (*RequestContext_OrgId) isRequestContext_ResourceOwner() {}

func (*RequestContext_Instance) isRequestContext_ResourceOwner() {}

type ListQuery struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Offset uint64 `protobuf:"varint,1,opt,name=offset,proto3" json:"offset,omitempty"`
	Limit  uint32 `protobuf:"varint,2,opt,name=limit,proto3" json:"limit,omitempty"`
	Asc    bool   `protobuf:"varint,3,opt,name=asc,proto3" json:"asc,omitempty"`
}

func (x *ListQuery) Reset() {
	*x = ListQuery{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_object_v2beta_object_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListQuery) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListQuery) ProtoMessage() {}

func (x *ListQuery) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_object_v2beta_object_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListQuery.ProtoReflect.Descriptor instead.
func (*ListQuery) Descriptor() ([]byte, []int) {
	return file_zitadel_object_v2beta_object_proto_rawDescGZIP(), []int{2}
}

func (x *ListQuery) GetOffset() uint64 {
	if x != nil {
		return x.Offset
	}
	return 0
}

func (x *ListQuery) GetLimit() uint32 {
	if x != nil {
		return x.Limit
	}
	return 0
}

func (x *ListQuery) GetAsc() bool {
	if x != nil {
		return x.Asc
	}
	return false
}

type Details struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// sequence represents the order of events. It's always counting
	//
	// on read: the sequence of the last event reduced by the projection
	//
	// on manipulation: the timestamp of the event(s) added by the manipulation
	Sequence uint64 `protobuf:"varint,1,opt,name=sequence,proto3" json:"sequence,omitempty"`
	// change_date is the timestamp when the object was changed
	//
	// on read: the timestamp of the last event reduced by the projection
	//
	// on manipulation: the timestamp of the event(s) added by the manipulation
	ChangeDate *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=change_date,json=changeDate,proto3" json:"change_date,omitempty"`
	// resource_owner is the organization or instance_id an object belongs to
	ResourceOwner string `protobuf:"bytes,3,opt,name=resource_owner,json=resourceOwner,proto3" json:"resource_owner,omitempty"`
}

func (x *Details) Reset() {
	*x = Details{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_object_v2beta_object_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Details) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Details) ProtoMessage() {}

func (x *Details) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_object_v2beta_object_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Details.ProtoReflect.Descriptor instead.
func (*Details) Descriptor() ([]byte, []int) {
	return file_zitadel_object_v2beta_object_proto_rawDescGZIP(), []int{3}
}

func (x *Details) GetSequence() uint64 {
	if x != nil {
		return x.Sequence
	}
	return 0
}

func (x *Details) GetChangeDate() *timestamppb.Timestamp {
	if x != nil {
		return x.ChangeDate
	}
	return nil
}

func (x *Details) GetResourceOwner() string {
	if x != nil {
		return x.ResourceOwner
	}
	return ""
}

type ListDetails struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TotalResult       uint64                 `protobuf:"varint,1,opt,name=total_result,json=totalResult,proto3" json:"total_result,omitempty"`
	ProcessedSequence uint64                 `protobuf:"varint,2,opt,name=processed_sequence,json=processedSequence,proto3" json:"processed_sequence,omitempty"`
	Timestamp         *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
}

func (x *ListDetails) Reset() {
	*x = ListDetails{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_object_v2beta_object_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListDetails) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListDetails) ProtoMessage() {}

func (x *ListDetails) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_object_v2beta_object_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListDetails.ProtoReflect.Descriptor instead.
func (*ListDetails) Descriptor() ([]byte, []int) {
	return file_zitadel_object_v2beta_object_proto_rawDescGZIP(), []int{4}
}

func (x *ListDetails) GetTotalResult() uint64 {
	if x != nil {
		return x.TotalResult
	}
	return 0
}

func (x *ListDetails) GetProcessedSequence() uint64 {
	if x != nil {
		return x.ProcessedSequence
	}
	return 0
}

func (x *ListDetails) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

var File_zitadel_object_v2beta_object_proto protoreflect.FileDescriptor

var file_zitadel_object_v2beta_object_proto_rawDesc = []byte{
	0x0a, 0x22, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x2f, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x2f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x6f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x1a, 0x1f, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e, 0x61, 0x70, 0x69,
	0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4f, 0x0a, 0x0c, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x73,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x17, 0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x05, 0x6f, 0x72, 0x67, 0x49, 0x64, 0x12, 0x1f,
	0x0a, 0x0a, 0x6f, 0x72, 0x67, 0x5f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x48, 0x00, 0x52, 0x09, 0x6f, 0x72, 0x67, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x42,
	0x05, 0x0a, 0x03, 0x6f, 0x72, 0x67, 0x22, 0x62, 0x0a, 0x0e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x12, 0x17, 0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x05, 0x6f, 0x72, 0x67, 0x49,
	0x64, 0x12, 0x25, 0x0a, 0x08, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x08, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x6a, 0x02, 0x08, 0x01, 0x48, 0x00, 0x52, 0x08,
	0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x42, 0x10, 0x0a, 0x0e, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x5f, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x22, 0xe4, 0x03, 0x0a, 0x09, 0x4c,
	0x69, 0x73, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x12, 0x20, 0x0a, 0x06, 0x6f, 0x66, 0x66, 0x73,
	0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x42, 0x08, 0x92, 0x41, 0x05, 0x4a, 0x03, 0x22,
	0x30, 0x22, 0x52, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x12, 0xaa, 0x02, 0x0a, 0x05, 0x6c,
	0x69, 0x6d, 0x69, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x42, 0x93, 0x02, 0x92, 0x41, 0x8f,
	0x02, 0x32, 0x87, 0x02, 0x4d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x20, 0x61, 0x6d, 0x6f, 0x75,
	0x6e, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x72, 0x65, 0x74,
	0x75, 0x72, 0x6e, 0x65, 0x64, 0x2e, 0x20, 0x54, 0x68, 0x65, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x20, 0x69, 0x73, 0x20, 0x73, 0x65, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x31, 0x30, 0x30,
	0x30, 0x20, 0x69, 0x6e, 0x20, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f,
	0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x62, 0x6c, 0x6f, 0x62, 0x2f, 0x6e, 0x65, 0x77,
	0x2d, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6d, 0x64, 0x2f,
	0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x2e,
	0x79, 0x61, 0x6d, 0x6c, 0x2e, 0x20, 0x49, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x69, 0x6d,
	0x69, 0x74, 0x20, 0x65, 0x78, 0x63, 0x65, 0x65, 0x64, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6d,
	0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65,
	0x64, 0x20, 0x5a, 0x49, 0x54, 0x41, 0x44, 0x45, 0x4c, 0x20, 0x77, 0x69, 0x6c, 0x6c, 0x20, 0x74,
	0x68, 0x72, 0x6f, 0x77, 0x20, 0x61, 0x6e, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2e, 0x20, 0x49,
	0x66, 0x20, 0x6e, 0x6f, 0x20, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x70, 0x72,
	0x65, 0x73, 0x65, 0x6e, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c,
	0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x61, 0x6b, 0x65, 0x6e, 0x2e, 0x4a, 0x03, 0x31, 0x30, 0x30,
	0x52, 0x05, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x2c, 0x0a, 0x03, 0x61, 0x73, 0x63, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x08, 0x42, 0x1a, 0x92, 0x41, 0x17, 0x32, 0x15, 0x64, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x20, 0x69, 0x73, 0x20, 0x64, 0x65, 0x73, 0x63, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67,
	0x52, 0x03, 0x61, 0x73, 0x63, 0x3a, 0x5a, 0x92, 0x41, 0x57, 0x0a, 0x55, 0x2a, 0x12, 0x47, 0x65,
	0x6e, 0x65, 0x72, 0x61, 0x6c, 0x20, 0x4c, 0x69, 0x73, 0x74, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x32, 0x3f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x75, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x69,
	0x66, 0x69, 0x63, 0x20, 0x6c, 0x69, 0x73, 0x74, 0x20, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73,
	0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x2c, 0x20, 0x6c, 0x69,
	0x6d, 0x69, 0x74, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x73, 0x63, 0x2f, 0x64, 0x65, 0x73, 0x63,
	0x2e, 0x22, 0xad, 0x01, 0x0a, 0x07, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x24, 0x0a,
	0x08, 0x73, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x42,
	0x08, 0x92, 0x41, 0x05, 0x4a, 0x03, 0x22, 0x32, 0x22, 0x52, 0x08, 0x73, 0x65, 0x71, 0x75, 0x65,
	0x6e, 0x63, 0x65, 0x12, 0x3b, 0x0a, 0x0b, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x64, 0x61,
	0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x44, 0x61, 0x74, 0x65,
	0x12, 0x3f, 0x0a, 0x0e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x6f, 0x77, 0x6e,
	0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x18, 0x92, 0x41, 0x15, 0x4a, 0x13, 0x22,
	0x36, 0x39, 0x36, 0x32, 0x39, 0x30, 0x32, 0x33, 0x39, 0x30, 0x36, 0x34, 0x38, 0x38, 0x33, 0x33,
	0x34, 0x22, 0x52, 0x0d, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4f, 0x77, 0x6e, 0x65,
	0x72, 0x22, 0xe1, 0x01, 0x0a, 0x0b, 0x4c, 0x69, 0x73, 0x74, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c,
	0x73, 0x12, 0x2b, 0x0a, 0x0c, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x72, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x42, 0x08, 0x92, 0x41, 0x05, 0x4a, 0x03, 0x22, 0x32,
	0x22, 0x52, 0x0b, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x3c,
	0x0a, 0x12, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x5f, 0x73, 0x65, 0x71, 0x75,
	0x65, 0x6e, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x42, 0x0d, 0x92, 0x41, 0x0a, 0x4a,
	0x08, 0x22, 0x32, 0x36, 0x37, 0x38, 0x33, 0x31, 0x22, 0x52, 0x11, 0x70, 0x72, 0x6f, 0x63, 0x65,
	0x73, 0x73, 0x65, 0x64, 0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x67, 0x0a, 0x09,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x2d, 0x92, 0x41, 0x2a,
	0x32, 0x28, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x73, 0x74, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x67,
	0x6f, 0x74, 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x3a, 0x5a, 0x38, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x7a, 0x69, 0x74, 0x61,
	0x64, 0x65, 0x6c, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x2f, 0x76, 0x32, 0x62, 0x65, 0x74, 0x61, 0x3b, 0x6f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_zitadel_object_v2beta_object_proto_rawDescOnce sync.Once
	file_zitadel_object_v2beta_object_proto_rawDescData = file_zitadel_object_v2beta_object_proto_rawDesc
)

func file_zitadel_object_v2beta_object_proto_rawDescGZIP() []byte {
	file_zitadel_object_v2beta_object_proto_rawDescOnce.Do(func() {
		file_zitadel_object_v2beta_object_proto_rawDescData = protoimpl.X.CompressGZIP(file_zitadel_object_v2beta_object_proto_rawDescData)
	})
	return file_zitadel_object_v2beta_object_proto_rawDescData
}

var file_zitadel_object_v2beta_object_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_zitadel_object_v2beta_object_proto_goTypes = []interface{}{
	(*Organisation)(nil),          // 0: zitadel.object.v2beta.Organisation
	(*RequestContext)(nil),        // 1: zitadel.object.v2beta.RequestContext
	(*ListQuery)(nil),             // 2: zitadel.object.v2beta.ListQuery
	(*Details)(nil),               // 3: zitadel.object.v2beta.Details
	(*ListDetails)(nil),           // 4: zitadel.object.v2beta.ListDetails
	(*timestamppb.Timestamp)(nil), // 5: google.protobuf.Timestamp
}
var file_zitadel_object_v2beta_object_proto_depIdxs = []int32{
	5, // 0: zitadel.object.v2beta.Details.change_date:type_name -> google.protobuf.Timestamp
	5, // 1: zitadel.object.v2beta.ListDetails.timestamp:type_name -> google.protobuf.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_zitadel_object_v2beta_object_proto_init() }
func file_zitadel_object_v2beta_object_proto_init() {
	if File_zitadel_object_v2beta_object_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_zitadel_object_v2beta_object_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Organisation); i {
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
		file_zitadel_object_v2beta_object_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RequestContext); i {
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
		file_zitadel_object_v2beta_object_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListQuery); i {
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
		file_zitadel_object_v2beta_object_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Details); i {
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
		file_zitadel_object_v2beta_object_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListDetails); i {
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
	file_zitadel_object_v2beta_object_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Organisation_OrgId)(nil),
		(*Organisation_OrgDomain)(nil),
	}
	file_zitadel_object_v2beta_object_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*RequestContext_OrgId)(nil),
		(*RequestContext_Instance)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_zitadel_object_v2beta_object_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_zitadel_object_v2beta_object_proto_goTypes,
		DependencyIndexes: file_zitadel_object_v2beta_object_proto_depIdxs,
		MessageInfos:      file_zitadel_object_v2beta_object_proto_msgTypes,
	}.Build()
	File_zitadel_object_v2beta_object_proto = out.File
	file_zitadel_object_v2beta_object_proto_rawDesc = nil
	file_zitadel_object_v2beta_object_proto_goTypes = nil
	file_zitadel_object_v2beta_object_proto_depIdxs = nil
}

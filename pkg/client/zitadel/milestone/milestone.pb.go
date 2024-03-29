// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.18.0
// source: zitadel/milestone/v1/milestone.proto

package milestone

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	_ "github.com/zitadel/zitadel-go/v2/pkg/client/zitadel/object"
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

type MilestoneType int32

const (
	MilestoneType_MILESTONE_TYPE_UNSPECIFIED                             MilestoneType = 0
	MilestoneType_MILESTONE_TYPE_INSTANCE_CREATED                        MilestoneType = 1
	MilestoneType_MILESTONE_TYPE_AUTHENTICATION_SUCCEEDED_ON_INSTANCE    MilestoneType = 2
	MilestoneType_MILESTONE_TYPE_PROJECT_CREATED                         MilestoneType = 3
	MilestoneType_MILESTONE_TYPE_APPLICATION_CREATED                     MilestoneType = 4
	MilestoneType_MILESTONE_TYPE_AUTHENTICATION_SUCCEEDED_ON_APPLICATION MilestoneType = 5
	MilestoneType_MILESTONE_TYPE_INSTANCE_DELETED                        MilestoneType = 6
)

// Enum value maps for MilestoneType.
var (
	MilestoneType_name = map[int32]string{
		0: "MILESTONE_TYPE_UNSPECIFIED",
		1: "MILESTONE_TYPE_INSTANCE_CREATED",
		2: "MILESTONE_TYPE_AUTHENTICATION_SUCCEEDED_ON_INSTANCE",
		3: "MILESTONE_TYPE_PROJECT_CREATED",
		4: "MILESTONE_TYPE_APPLICATION_CREATED",
		5: "MILESTONE_TYPE_AUTHENTICATION_SUCCEEDED_ON_APPLICATION",
		6: "MILESTONE_TYPE_INSTANCE_DELETED",
	}
	MilestoneType_value = map[string]int32{
		"MILESTONE_TYPE_UNSPECIFIED":                             0,
		"MILESTONE_TYPE_INSTANCE_CREATED":                        1,
		"MILESTONE_TYPE_AUTHENTICATION_SUCCEEDED_ON_INSTANCE":    2,
		"MILESTONE_TYPE_PROJECT_CREATED":                         3,
		"MILESTONE_TYPE_APPLICATION_CREATED":                     4,
		"MILESTONE_TYPE_AUTHENTICATION_SUCCEEDED_ON_APPLICATION": 5,
		"MILESTONE_TYPE_INSTANCE_DELETED":                        6,
	}
)

func (x MilestoneType) Enum() *MilestoneType {
	p := new(MilestoneType)
	*p = x
	return p
}

func (x MilestoneType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MilestoneType) Descriptor() protoreflect.EnumDescriptor {
	return file_zitadel_milestone_v1_milestone_proto_enumTypes[0].Descriptor()
}

func (MilestoneType) Type() protoreflect.EnumType {
	return &file_zitadel_milestone_v1_milestone_proto_enumTypes[0]
}

func (x MilestoneType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MilestoneType.Descriptor instead.
func (MilestoneType) EnumDescriptor() ([]byte, []int) {
	return file_zitadel_milestone_v1_milestone_proto_rawDescGZIP(), []int{0}
}

type MilestoneFieldName int32

const (
	MilestoneFieldName_MILESTONE_FIELD_NAME_UNSPECIFIED  MilestoneFieldName = 0
	MilestoneFieldName_MILESTONE_FIELD_NAME_TYPE         MilestoneFieldName = 1
	MilestoneFieldName_MILESTONE_FIELD_NAME_REACHED_DATE MilestoneFieldName = 2
)

// Enum value maps for MilestoneFieldName.
var (
	MilestoneFieldName_name = map[int32]string{
		0: "MILESTONE_FIELD_NAME_UNSPECIFIED",
		1: "MILESTONE_FIELD_NAME_TYPE",
		2: "MILESTONE_FIELD_NAME_REACHED_DATE",
	}
	MilestoneFieldName_value = map[string]int32{
		"MILESTONE_FIELD_NAME_UNSPECIFIED":  0,
		"MILESTONE_FIELD_NAME_TYPE":         1,
		"MILESTONE_FIELD_NAME_REACHED_DATE": 2,
	}
)

func (x MilestoneFieldName) Enum() *MilestoneFieldName {
	p := new(MilestoneFieldName)
	*p = x
	return p
}

func (x MilestoneFieldName) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MilestoneFieldName) Descriptor() protoreflect.EnumDescriptor {
	return file_zitadel_milestone_v1_milestone_proto_enumTypes[1].Descriptor()
}

func (MilestoneFieldName) Type() protoreflect.EnumType {
	return &file_zitadel_milestone_v1_milestone_proto_enumTypes[1]
}

func (x MilestoneFieldName) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MilestoneFieldName.Descriptor instead.
func (MilestoneFieldName) EnumDescriptor() ([]byte, []int) {
	return file_zitadel_milestone_v1_milestone_proto_rawDescGZIP(), []int{1}
}

type Milestone struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type        MilestoneType          `protobuf:"varint,2,opt,name=type,proto3,enum=zitadel.milestone.v1.MilestoneType" json:"type,omitempty"`
	ReachedDate *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=reached_date,json=reachedDate,proto3" json:"reached_date,omitempty"`
}

func (x *Milestone) Reset() {
	*x = Milestone{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_milestone_v1_milestone_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Milestone) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Milestone) ProtoMessage() {}

func (x *Milestone) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_milestone_v1_milestone_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Milestone.ProtoReflect.Descriptor instead.
func (*Milestone) Descriptor() ([]byte, []int) {
	return file_zitadel_milestone_v1_milestone_proto_rawDescGZIP(), []int{0}
}

func (x *Milestone) GetType() MilestoneType {
	if x != nil {
		return x.Type
	}
	return MilestoneType_MILESTONE_TYPE_UNSPECIFIED
}

func (x *Milestone) GetReachedDate() *timestamppb.Timestamp {
	if x != nil {
		return x.ReachedDate
	}
	return nil
}

type MilestoneQuery struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Query:
	//
	//	*MilestoneQuery_IsReachedQuery
	Query isMilestoneQuery_Query `protobuf_oneof:"query"`
}

func (x *MilestoneQuery) Reset() {
	*x = MilestoneQuery{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_milestone_v1_milestone_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MilestoneQuery) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MilestoneQuery) ProtoMessage() {}

func (x *MilestoneQuery) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_milestone_v1_milestone_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MilestoneQuery.ProtoReflect.Descriptor instead.
func (*MilestoneQuery) Descriptor() ([]byte, []int) {
	return file_zitadel_milestone_v1_milestone_proto_rawDescGZIP(), []int{1}
}

func (m *MilestoneQuery) GetQuery() isMilestoneQuery_Query {
	if m != nil {
		return m.Query
	}
	return nil
}

func (x *MilestoneQuery) GetIsReachedQuery() *IsReachedQuery {
	if x, ok := x.GetQuery().(*MilestoneQuery_IsReachedQuery); ok {
		return x.IsReachedQuery
	}
	return nil
}

type isMilestoneQuery_Query interface {
	isMilestoneQuery_Query()
}

type MilestoneQuery_IsReachedQuery struct {
	IsReachedQuery *IsReachedQuery `protobuf:"bytes,1,opt,name=is_reached_query,json=isReachedQuery,proto3,oneof"`
}

func (*MilestoneQuery_IsReachedQuery) isMilestoneQuery_Query() {}

type IsReachedQuery struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Reached bool `protobuf:"varint,1,opt,name=reached,proto3" json:"reached,omitempty"`
}

func (x *IsReachedQuery) Reset() {
	*x = IsReachedQuery{}
	if protoimpl.UnsafeEnabled {
		mi := &file_zitadel_milestone_v1_milestone_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IsReachedQuery) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IsReachedQuery) ProtoMessage() {}

func (x *IsReachedQuery) ProtoReflect() protoreflect.Message {
	mi := &file_zitadel_milestone_v1_milestone_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IsReachedQuery.ProtoReflect.Descriptor instead.
func (*IsReachedQuery) Descriptor() ([]byte, []int) {
	return file_zitadel_milestone_v1_milestone_proto_rawDescGZIP(), []int{2}
}

func (x *IsReachedQuery) GetReached() bool {
	if x != nil {
		return x.Reached
	}
	return false
}

var File_zitadel_milestone_v1_milestone_proto protoreflect.FileDescriptor

var file_zitadel_milestone_v1_milestone_proto_rawDesc = []byte{
	0x0a, 0x24, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x6d, 0x69, 0x6c, 0x65, 0x73, 0x74,
	0x6f, 0x6e, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x69, 0x6c, 0x65, 0x73, 0x74, 0x6f, 0x6e, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x14, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e,
	0x6d, 0x69, 0x6c, 0x65, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x14, 0x7a, 0x69,
	0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c,
	0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e, 0x61, 0x70, 0x69,
	0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x92, 0x01, 0x0a,
	0x09, 0x4d, 0x69, 0x6c, 0x65, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x12, 0x37, 0x0a, 0x04, 0x74, 0x79,
	0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x23, 0x2e, 0x7a, 0x69, 0x74, 0x61, 0x64,
	0x65, 0x6c, 0x2e, 0x6d, 0x69, 0x6c, 0x65, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x4d, 0x69, 0x6c, 0x65, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x12, 0x3d, 0x0a, 0x0c, 0x72, 0x65, 0x61, 0x63, 0x68, 0x65, 0x64, 0x5f, 0x64,
	0x61, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0b, 0x72, 0x65, 0x61, 0x63, 0x68, 0x65, 0x64, 0x44, 0x61,
	0x74, 0x65, 0x4a, 0x04, 0x08, 0x01, 0x10, 0x02, 0x52, 0x07, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c,
	0x73, 0x22, 0x6b, 0x0a, 0x0e, 0x4d, 0x69, 0x6c, 0x65, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x51, 0x75,
	0x65, 0x72, 0x79, 0x12, 0x50, 0x0a, 0x10, 0x69, 0x73, 0x5f, 0x72, 0x65, 0x61, 0x63, 0x68, 0x65,
	0x64, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e,
	0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2e, 0x6d, 0x69, 0x6c, 0x65, 0x73, 0x74, 0x6f, 0x6e,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x73, 0x52, 0x65, 0x61, 0x63, 0x68, 0x65, 0x64, 0x51, 0x75,
	0x65, 0x72, 0x79, 0x48, 0x00, 0x52, 0x0e, 0x69, 0x73, 0x52, 0x65, 0x61, 0x63, 0x68, 0x65, 0x64,
	0x51, 0x75, 0x65, 0x72, 0x79, 0x42, 0x07, 0x0a, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22, 0x48,
	0x0a, 0x0e, 0x49, 0x73, 0x52, 0x65, 0x61, 0x63, 0x68, 0x65, 0x64, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x12, 0x36, 0x0a, 0x07, 0x72, 0x65, 0x61, 0x63, 0x68, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x08, 0x42, 0x1c, 0x92, 0x41, 0x19, 0x32, 0x17, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x72, 0x65, 0x61,
	0x63, 0x68, 0x65, 0x64, 0x20, 0x6d, 0x69, 0x6c, 0x65, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x73, 0x52,
	0x07, 0x72, 0x65, 0x61, 0x63, 0x68, 0x65, 0x64, 0x2a, 0xba, 0x02, 0x0a, 0x0d, 0x4d, 0x69, 0x6c,
	0x65, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1e, 0x0a, 0x1a, 0x4d, 0x49,
	0x4c, 0x45, 0x53, 0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53,
	0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x23, 0x0a, 0x1f, 0x4d, 0x49,
	0x4c, 0x45, 0x53, 0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x49, 0x4e, 0x53,
	0x54, 0x41, 0x4e, 0x43, 0x45, 0x5f, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x44, 0x10, 0x01, 0x12,
	0x37, 0x0a, 0x33, 0x4d, 0x49, 0x4c, 0x45, 0x53, 0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x54, 0x59, 0x50,
	0x45, 0x5f, 0x41, 0x55, 0x54, 0x48, 0x45, 0x4e, 0x54, 0x49, 0x43, 0x41, 0x54, 0x49, 0x4f, 0x4e,
	0x5f, 0x53, 0x55, 0x43, 0x43, 0x45, 0x45, 0x44, 0x45, 0x44, 0x5f, 0x4f, 0x4e, 0x5f, 0x49, 0x4e,
	0x53, 0x54, 0x41, 0x4e, 0x43, 0x45, 0x10, 0x02, 0x12, 0x22, 0x0a, 0x1e, 0x4d, 0x49, 0x4c, 0x45,
	0x53, 0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x50, 0x52, 0x4f, 0x4a, 0x45,
	0x43, 0x54, 0x5f, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x44, 0x10, 0x03, 0x12, 0x26, 0x0a, 0x22,
	0x4d, 0x49, 0x4c, 0x45, 0x53, 0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x41,
	0x50, 0x50, 0x4c, 0x49, 0x43, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x43, 0x52, 0x45, 0x41, 0x54,
	0x45, 0x44, 0x10, 0x04, 0x12, 0x3a, 0x0a, 0x36, 0x4d, 0x49, 0x4c, 0x45, 0x53, 0x54, 0x4f, 0x4e,
	0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x41, 0x55, 0x54, 0x48, 0x45, 0x4e, 0x54, 0x49, 0x43,
	0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x55, 0x43, 0x43, 0x45, 0x45, 0x44, 0x45, 0x44, 0x5f,
	0x4f, 0x4e, 0x5f, 0x41, 0x50, 0x50, 0x4c, 0x49, 0x43, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x10, 0x05,
	0x12, 0x23, 0x0a, 0x1f, 0x4d, 0x49, 0x4c, 0x45, 0x53, 0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x54, 0x59,
	0x50, 0x45, 0x5f, 0x49, 0x4e, 0x53, 0x54, 0x41, 0x4e, 0x43, 0x45, 0x5f, 0x44, 0x45, 0x4c, 0x45,
	0x54, 0x45, 0x44, 0x10, 0x06, 0x2a, 0x80, 0x01, 0x0a, 0x12, 0x4d, 0x69, 0x6c, 0x65, 0x73, 0x74,
	0x6f, 0x6e, 0x65, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x24, 0x0a, 0x20,
	0x4d, 0x49, 0x4c, 0x45, 0x53, 0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x46, 0x49, 0x45, 0x4c, 0x44, 0x5f,
	0x4e, 0x41, 0x4d, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44,
	0x10, 0x00, 0x12, 0x1d, 0x0a, 0x19, 0x4d, 0x49, 0x4c, 0x45, 0x53, 0x54, 0x4f, 0x4e, 0x45, 0x5f,
	0x46, 0x49, 0x45, 0x4c, 0x44, 0x5f, 0x4e, 0x41, 0x4d, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x10,
	0x01, 0x12, 0x25, 0x0a, 0x21, 0x4d, 0x49, 0x4c, 0x45, 0x53, 0x54, 0x4f, 0x4e, 0x45, 0x5f, 0x46,
	0x49, 0x45, 0x4c, 0x44, 0x5f, 0x4e, 0x41, 0x4d, 0x45, 0x5f, 0x52, 0x45, 0x41, 0x43, 0x48, 0x45,
	0x44, 0x5f, 0x44, 0x41, 0x54, 0x45, 0x10, 0x02, 0x42, 0x2f, 0x5a, 0x2d, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x7a, 0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x7a,
	0x69, 0x74, 0x61, 0x64, 0x65, 0x6c, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f,
	0x6d, 0x69, 0x6c, 0x65, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_zitadel_milestone_v1_milestone_proto_rawDescOnce sync.Once
	file_zitadel_milestone_v1_milestone_proto_rawDescData = file_zitadel_milestone_v1_milestone_proto_rawDesc
)

func file_zitadel_milestone_v1_milestone_proto_rawDescGZIP() []byte {
	file_zitadel_milestone_v1_milestone_proto_rawDescOnce.Do(func() {
		file_zitadel_milestone_v1_milestone_proto_rawDescData = protoimpl.X.CompressGZIP(file_zitadel_milestone_v1_milestone_proto_rawDescData)
	})
	return file_zitadel_milestone_v1_milestone_proto_rawDescData
}

var file_zitadel_milestone_v1_milestone_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_zitadel_milestone_v1_milestone_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_zitadel_milestone_v1_milestone_proto_goTypes = []interface{}{
	(MilestoneType)(0),            // 0: zitadel.milestone.v1.MilestoneType
	(MilestoneFieldName)(0),       // 1: zitadel.milestone.v1.MilestoneFieldName
	(*Milestone)(nil),             // 2: zitadel.milestone.v1.Milestone
	(*MilestoneQuery)(nil),        // 3: zitadel.milestone.v1.MilestoneQuery
	(*IsReachedQuery)(nil),        // 4: zitadel.milestone.v1.IsReachedQuery
	(*timestamppb.Timestamp)(nil), // 5: google.protobuf.Timestamp
}
var file_zitadel_milestone_v1_milestone_proto_depIdxs = []int32{
	0, // 0: zitadel.milestone.v1.Milestone.type:type_name -> zitadel.milestone.v1.MilestoneType
	5, // 1: zitadel.milestone.v1.Milestone.reached_date:type_name -> google.protobuf.Timestamp
	4, // 2: zitadel.milestone.v1.MilestoneQuery.is_reached_query:type_name -> zitadel.milestone.v1.IsReachedQuery
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_zitadel_milestone_v1_milestone_proto_init() }
func file_zitadel_milestone_v1_milestone_proto_init() {
	if File_zitadel_milestone_v1_milestone_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_zitadel_milestone_v1_milestone_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Milestone); i {
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
		file_zitadel_milestone_v1_milestone_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MilestoneQuery); i {
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
		file_zitadel_milestone_v1_milestone_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IsReachedQuery); i {
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
	file_zitadel_milestone_v1_milestone_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*MilestoneQuery_IsReachedQuery)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_zitadel_milestone_v1_milestone_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_zitadel_milestone_v1_milestone_proto_goTypes,
		DependencyIndexes: file_zitadel_milestone_v1_milestone_proto_depIdxs,
		EnumInfos:         file_zitadel_milestone_v1_milestone_proto_enumTypes,
		MessageInfos:      file_zitadel_milestone_v1_milestone_proto_msgTypes,
	}.Build()
	File_zitadel_milestone_v1_milestone_proto = out.File
	file_zitadel_milestone_v1_milestone_proto_rawDesc = nil
	file_zitadel_milestone_v1_milestone_proto_goTypes = nil
	file_zitadel_milestone_v1_milestone_proto_depIdxs = nil
}

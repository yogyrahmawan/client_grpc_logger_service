// Code generated by protoc-gen-go. DO NOT EDIT.
// source: logger_response.proto

package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type LoggerResponse struct {
	Status string `protobuf:"bytes,1,opt,name=Status" json:"Status,omitempty"`
}

func (m *LoggerResponse) Reset()                    { *m = LoggerResponse{} }
func (m *LoggerResponse) String() string            { return proto.CompactTextString(m) }
func (*LoggerResponse) ProtoMessage()               {}
func (*LoggerResponse) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{0} }

func (m *LoggerResponse) GetStatus() string {
	if m != nil {
		return m.Status
	}
	return ""
}

func init() {
	proto.RegisterType((*LoggerResponse)(nil), "pb.LoggerResponse")
}

func init() { proto.RegisterFile("logger_response.proto", fileDescriptor2) }

var fileDescriptor2 = []byte{
	// 85 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0xcd, 0xc9, 0x4f, 0x4f,
	0x4f, 0x2d, 0x8a, 0x2f, 0x4a, 0x2d, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e, 0xd5, 0x2b, 0x28, 0xca, 0x2f,
	0xc9, 0x17, 0x62, 0x2a, 0x48, 0x52, 0xd2, 0xe0, 0xe2, 0xf3, 0x01, 0x4b, 0x06, 0x41, 0xe5, 0x84,
	0xc4, 0xb8, 0xd8, 0x82, 0x4b, 0x12, 0x4b, 0x4a, 0x8b, 0x25, 0x18, 0x15, 0x18, 0x35, 0x38, 0x83,
	0xa0, 0xbc, 0x24, 0x36, 0xb0, 0x26, 0x63, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0x4d, 0x5a, 0xa5,
	0xd9, 0x4d, 0x00, 0x00, 0x00,
}

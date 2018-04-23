// Code generated by protoc-gen-go. DO NOT EDIT.
// source: logger_service.proto

package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for LoggerService service

type LoggerServiceClient interface {
	SendLog(ctx context.Context, in *LoggerMessage, opts ...grpc.CallOption) (*LoggerResponse, error)
	GetLog(ctx context.Context, in *GetLoggerRequest, opts ...grpc.CallOption) (*LoggerResponsesMessage, error)
}

type loggerServiceClient struct {
	cc *grpc.ClientConn
}

func NewLoggerServiceClient(cc *grpc.ClientConn) LoggerServiceClient {
	return &loggerServiceClient{cc}
}

func (c *loggerServiceClient) SendLog(ctx context.Context, in *LoggerMessage, opts ...grpc.CallOption) (*LoggerResponse, error) {
	out := new(LoggerResponse)
	err := grpc.Invoke(ctx, "/pb.LoggerService/SendLog", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *loggerServiceClient) GetLog(ctx context.Context, in *GetLoggerRequest, opts ...grpc.CallOption) (*LoggerResponsesMessage, error) {
	out := new(LoggerResponsesMessage)
	err := grpc.Invoke(ctx, "/pb.LoggerService/GetLog", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for LoggerService service

type LoggerServiceServer interface {
	SendLog(context.Context, *LoggerMessage) (*LoggerResponse, error)
	GetLog(context.Context, *GetLoggerRequest) (*LoggerResponsesMessage, error)
}

func RegisterLoggerServiceServer(s *grpc.Server, srv LoggerServiceServer) {
	s.RegisterService(&_LoggerService_serviceDesc, srv)
}

func _LoggerService_SendLog_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoggerMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LoggerServiceServer).SendLog(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.LoggerService/SendLog",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LoggerServiceServer).SendLog(ctx, req.(*LoggerMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _LoggerService_GetLog_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetLoggerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LoggerServiceServer).GetLog(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.LoggerService/GetLog",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LoggerServiceServer).GetLog(ctx, req.(*GetLoggerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _LoggerService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "pb.LoggerService",
	HandlerType: (*LoggerServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SendLog",
			Handler:    _LoggerService_SendLog_Handler,
		},
		{
			MethodName: "GetLog",
			Handler:    _LoggerService_GetLog_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "logger_service.proto",
}

func init() { proto.RegisterFile("logger_service.proto", fileDescriptor4) }

var fileDescriptor4 = []byte{
	// 243 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0xc9, 0xc9, 0x4f, 0x4f,
	0x4f, 0x2d, 0x8a, 0x2f, 0x4e, 0x2d, 0x2a, 0xcb, 0x4c, 0x4e, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9,
	0x17, 0x62, 0x2a, 0x48, 0x92, 0xe2, 0x81, 0xc8, 0x40, 0x44, 0xa4, 0x44, 0xa1, 0xea, 0x8a, 0x52,
	0x8b, 0x0b, 0xf2, 0xf3, 0x8a, 0xa1, 0x0a, 0xa5, 0xc4, 0xd0, 0x84, 0x8b, 0xa1, 0xe2, 0x12, 0xe9,
	0xa9, 0x25, 0xf1, 0x70, 0xb9, 0xc2, 0xd2, 0xd4, 0xe2, 0x12, 0xa8, 0x8c, 0x4c, 0x7a, 0x7e, 0x7e,
	0x7a, 0x4e, 0xaa, 0x7e, 0x62, 0x41, 0xa6, 0x7e, 0x62, 0x5e, 0x5e, 0x7e, 0x49, 0x62, 0x49, 0x66,
	0x7e, 0x1e, 0x54, 0x9f, 0xd1, 0x3d, 0x46, 0x2e, 0x5e, 0x1f, 0xb0, 0xb6, 0x60, 0x88, 0x83, 0x84,
	0x0c, 0xb8, 0xd8, 0x83, 0x53, 0xf3, 0x52, 0x7c, 0xf2, 0xd3, 0x85, 0x04, 0xf5, 0x0a, 0x92, 0xf4,
	0x20, 0xb2, 0xbe, 0xa9, 0xc5, 0xc5, 0x89, 0xe9, 0xa9, 0x52, 0x42, 0x08, 0xa1, 0x20, 0xa8, 0x13,
	0x84, 0x66, 0x31, 0x72, 0xb1, 0xb9, 0xa7, 0x96, 0x80, 0x74, 0x88, 0x80, 0xa4, 0x21, 0x6c, 0xb0,
	0x0a, 0xb0, 0x43, 0xa4, 0xa4, 0x30, 0x35, 0x15, 0x43, 0x0d, 0x54, 0x8a, 0x6b, 0xba, 0xfc, 0x64,
	0x32, 0x53, 0x84, 0x10, 0x0f, 0xd8, 0x81, 0x65, 0x86, 0xfa, 0x39, 0xf9, 0xe9, 0xc5, 0x51, 0x5a,
	0x42, 0x1a, 0xc8, 0x7c, 0xfd, 0x6a, 0x68, 0x70, 0xc5, 0xe7, 0x25, 0xe6, 0xa6, 0xd6, 0xea, 0x23,
	0xf3, 0xa2, 0x64, 0x84, 0xa4, 0x50, 0xd5, 0xe6, 0xa4, 0x96, 0xa5, 0xe6, 0xd4, 0xea, 0x83, 0xa9,
	0x24, 0x36, 0xb0, 0x3f, 0x8d, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0xba, 0x27, 0x85, 0x5f, 0x78,
	0x01, 0x00, 0x00,
}

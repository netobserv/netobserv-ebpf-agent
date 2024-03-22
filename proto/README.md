# Protobuf + gRPC

Golang files are automatically updated when running `make generate` according to `.proto` files content. 

# Development

## Manually update flow gRPC

Run the following commands to update `flow.pb.go` and `flow_grpc.pb.go`:

```bash
protoc --go_out=./pkg/ ./proto/flow.proto
protoc --go-grpc_out=./pkg/ ./proto/flow.proto
```

## Manually update packet gRPC

Run the following commands to update `packet.pb.go` and `packet_grpc.pb.go`:

```bash
protoc --go_out=./pkg/ ./proto/packet.proto
protoc --go-grpc_out=./pkg/ ./proto/packet.proto
```
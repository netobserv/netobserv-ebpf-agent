# Update flow gRPC
```bash
protoc --go_out=./pkg/ ./proto/flow.proto
protoc --go-grpc_out=./pkg/ ./proto/flow.proto
```

# Update packet gRPC

Run the following commands to update `packet.pb.go` and `packet_grpc.pb.go`:

```bash
protoc --go_out=./pkg/ ./proto/packet.proto
protoc --go-grpc_out=./pkg/ ./proto/packet.proto
```
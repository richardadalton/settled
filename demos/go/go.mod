module github.com/richardadalton/settled/demos/go

go 1.22

require github.com/richardadalton/settled/sdks/go v0.0.0

require (
	golang.org/x/net v0.22.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
	google.golang.org/grpc v1.64.0 // indirect
	google.golang.org/protobuf v1.34.0 // indirect
)

replace github.com/richardadalton/settled/sdks/go => ../../sdks/go

module github.com/x00real/envoy-ip-filter

go 1.24

require github.com/envoyproxy/envoy v1.34.1

require google.golang.org/protobuf v1.36.6

require (
	github.com/cncf/xds/go v0.0.0-20250501225837-2ac532fd4443
	github.com/hashicorp/golang-lru/v2 v2.0.7
)

require (
	cel.dev/expr v0.15.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.0.4 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230822172742-b8732ec3820d // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
)

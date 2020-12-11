main.wasm:
	GOOS=js GOARCH=wasm go build -o server/static/client.wasm client/client.go

ALL: client.wasm
# Golang WebAssembly AES256 + Diffie Hellman 
This code is a golang web assembly module which enabled AES256 encryption and Diffie Hellman handshakes.

# Functionality
 - Diffie Hellman P512 curve Handshakes + Key generation
 - AES256 Encryption / Decryption
 - WASM status check function
 - Error handling
 - WASM shutdown function
 - WASM Panic test function

# Examples
For example you can look at the index.html inside the "example" folder. You can also run the "server.go" file to spawn a temp webserver for testing.
```bash
$ cd example
$ go run .
```

# Building the WASM
```bash
$ GOOS=js GOARCH=wasm go build -o  wae.wasm

```
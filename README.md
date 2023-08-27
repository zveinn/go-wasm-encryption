# Golang WebAssembly AES256 + Diffie Hellman 
This code is a golang web assembly module which enabled AES256 encryption and Diffie Hellman handshakes.

# Functionality
 - Diffie Hellman P512 curve Handshakes + Key generation
 - AES256 Encryption / Decryption
 - WASM status check function
 - Error handling
 - WASM shutdown function
 - WASM Panic test function

# Building the WASM
```bash
$ GOOS=js GOARCH=wasm go build -o  wae.wasm

```

# Examples
For example you can look at the index.html inside the "example" folder. You can also run the "server.go" file to spawn a temp webserver for testing.
```bash
$ cd example
$ go run .
```

# Diffie Hellman Handshakes
This module can be used to handshake with a server or another user in whichever system you are developing. <br/>
Each back-and-forth handshake will consist of two "one-time-key" requests each one having their own UUID.
```golang
type OTK_REQUEST struct {
	X     *big.Int
	Y     *big.Int
	AUUID string
	BUUID string
}
```
These UUIDs are used to indentify matching handshake requests. <br/>
If you are handshaking with a server you can copy the "OTK_REQUEST" struct or make your own. 

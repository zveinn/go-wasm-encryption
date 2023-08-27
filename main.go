package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"runtime/debug"
	"syscall/js"

	"github.com/google/uuid"
)

var SHUTDOWN = make(chan bool, 1)

var HANDSHAKE_MAP = make(map[string]*HANDSHAKE)

type HANDSHAKE struct {
	Req *OTK_REQUEST
	PK  *ecdsa.PrivateKey
}

type CustomError struct {
	Message string
	Error   bool
}

type OTK_REQUEST struct {
	X     *big.Int
	Y     *big.Int
	AUUID string
	BUUID string
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Println(r, string(debug.Stack()))
		}
	}()

	fmt.Println("<< WebAssembly Encryption Loaded >>")

	js.Global().Set("wae_GenA", GenA())
	js.Global().Set("wae_AcceptB_GenKeyForA", AcceptB_GenKeyForA())

	js.Global().Set("wae_GenB", GenB())
	js.Global().Set("wae_AcceptA_GenKeyForB", AcceptA_GenKeyForB())

	js.Global().Set("wae_Encrypt", JSEncrypt())
	js.Global().Set("wae_Decrypt", JSDecrypt())

	js.Global().Set("wae_Shutdown", shutdown())
	js.Global().Set("wae_Status", status())
	js.Global().Set("wae_PanicTest", panicTest())

	<-SHUTDOWN
}

func ReturnError(msg string) string {
	x := new(CustomError)
	x.Error = true
	x.Message = msg

	outB, err := json.Marshal(x)
	if err != nil {
		return err.Error()
	}

	return string(outB)
}

func GenA() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				log.Println(r, string(debug.Stack()))
			}
		}()

		PK, R, err := GENERATE_KEY_AND_REQUEST()
		if err != nil {
			return ReturnError(err.Error())
		}

		R.AUUID = uuid.NewString()
		HANDSHAKE_MAP[R.AUUID] = new(HANDSHAKE)
		HANDSHAKE_MAP[R.AUUID].Req = R
		HANDSHAKE_MAP[R.AUUID].PK = PK

		outR, err := json.Marshal(R)
		if err != nil {
			return ReturnError(err.Error())
		}

		return string(outR)

	})
	return jsonFunc
}

func GenB() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				log.Println(r, string(debug.Stack()))
			}
		}()

		REQ := args[0].String()
		OTKA := new(OTK_REQUEST)
		err := json.Unmarshal([]byte(REQ), OTKA)
		if err != nil {
			return ReturnError(err.Error())
		}

		PK, R, err := GENERATE_KEY_AND_REQUEST()
		if err != nil {
			return ReturnError(err.Error())
		}

		R.AUUID = OTKA.AUUID

		R.BUUID = uuid.NewString()
		HANDSHAKE_MAP[R.BUUID] = new(HANDSHAKE)
		HANDSHAKE_MAP[R.BUUID].Req = R
		HANDSHAKE_MAP[R.BUUID].PK = PK

		outR, err := json.Marshal(R)
		if err != nil {
			return ReturnError(err.Error())
		}

		return string(outR)

	})
	return jsonFunc
}

func AcceptA_GenKeyForB() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				log.Println(r, string(debug.Stack()))
			}
		}()

		OTKARaw := args[0].String()
		OTKA := new(OTK_REQUEST)
		err := json.Unmarshal([]byte(OTKARaw), OTKA)
		if err != nil {
			return ReturnError(err.Error())
		}

		OTKBRaw := args[1].String()
		OTKB := new(OTK_REQUEST)
		err = json.Unmarshal([]byte(OTKBRaw), OTKB)
		if err != nil {
			return ReturnError(err.Error())
		}

		HANDSHAKE, ok := HANDSHAKE_MAP[OTKB.BUUID]
		if !ok {
			return ReturnError(err.Error())
		}

		KEY, err := GENERATE_KEY_FROM_REQUEST(HANDSHAKE.PK, OTKA)
		outKEY := make([]byte, len(KEY))
		for i := range KEY {
			outKEY[i] = KEY[i]
		}

		arrayConstructor := js.Global().Get("Uint8Array")
		dataJS := arrayConstructor.New(len(outKEY))
		js.CopyBytesToJS(dataJS, outKEY)

		return dataJS

	})
	return jsonFunc
}

func AcceptB_GenKeyForA() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				log.Println(r, string(debug.Stack()))
			}
		}()

		OTKBRaw := args[0].String()
		OTKB := new(OTK_REQUEST)
		err := json.Unmarshal([]byte(OTKBRaw), OTKB)
		if err != nil {
			return ReturnError(err.Error())
		}

		OTKARaw := args[1].String()
		OTKA := new(OTK_REQUEST)
		err = json.Unmarshal([]byte(OTKARaw), OTKA)
		if err != nil {
			return ReturnError(err.Error())
		}

		HANDSHAKE, ok := HANDSHAKE_MAP[OTKB.AUUID]
		if !ok {
			return ReturnError(err.Error())
		}

		KEY, err := GENERATE_KEY_FROM_REQUEST(HANDSHAKE.PK, OTKB)
		outKEY := make([]byte, len(KEY))
		for i := range KEY {
			outKEY[i] = KEY[i]
		}

		arrayConstructor := js.Global().Get("Uint8Array")
		dataJS := arrayConstructor.New(len(outKEY))
		js.CopyBytesToJS(dataJS, outKEY)

		return dataJS

	})
	return jsonFunc
}

func GENERATE_KEY_AND_REQUEST() (PK *ecdsa.PrivateKey, R *OTK_REQUEST, err error) {

	E := elliptic.P521()
	PK, err = ecdsa.GenerateKey(E, crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	R = new(OTK_REQUEST)
	R.X = PK.PublicKey.X
	R.Y = PK.PublicKey.Y
	return
}

func GENERATE_KEY_FROM_REQUEST(PK *ecdsa.PrivateKey, R *OTK_REQUEST) (KEY [32]byte, err error) {
	var CCKeyb *big.Int
	defer func() {
		if r := recover(); r != nil {
			log.Println(r, string(debug.Stack()))
		}
		CCKeyb = nil
	}()

	CCKeyb, _ = PK.Curve.ScalarMult(R.X, R.Y, PK.D.Bytes())
	KEY = sha256.Sum256(CCKeyb.Bytes())
	return
}

func JSEncrypt() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				log.Println(r, string(debug.Stack()))
			}
		}()

		keyBytes := args[0]
		keyBuf := make([]byte, keyBytes.Get("length").Int())
		_ = js.CopyBytesToGo(keyBuf, keyBytes)

		dataBytes := args[1]
		dataBuf := make([]byte, dataBytes.Get("length").Int())
		_ = js.CopyBytesToGo(dataBuf, dataBytes)

		x, err := Encrypt(dataBuf, keyBuf)
		if err != nil {
			return ReturnError(err.Error())
		}

		arrayConstructor := js.Global().Get("Uint8Array")
		dataJS := arrayConstructor.New(len(x))
		js.CopyBytesToJS(dataJS, x)

		return dataJS
	})

	return jsonFunc
}

func JSDecrypt() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				log.Println(r, string(debug.Stack()))
			}
		}()

		keyBytes := args[0]
		keyBuf := make([]byte, keyBytes.Get("length").Int())
		_ = js.CopyBytesToGo(keyBuf, keyBytes)

		dataBytes := args[1]
		dataBuf := make([]byte, dataBytes.Get("length").Int())
		_ = js.CopyBytesToGo(dataBuf, dataBytes)

		x, err := Decrypt(dataBuf, keyBuf)
		if err != nil {
			return ReturnError(err.Error())
		}

		arrayConstructor := js.Global().Get("Uint8Array")
		dataJS := arrayConstructor.New(len(x))
		js.CopyBytesToJS(dataJS, x)

		return dataJS
	})

	return jsonFunc
}

func Encrypt(text, key []byte) (out []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	out = make([]byte, aes.BlockSize+len(b))
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(out[aes.BlockSize:], []byte(b))
	return
}

func Decrypt(text, key []byte) (out []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("Key is too short")
	}

	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	temp := make([]byte, len(text))
	cfb.XORKeyStream(temp, text)
	out, err = base64.StdEncoding.DecodeString(string(temp))
	if err != nil {
		return nil, err
	}
	return
}

func shutdown() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				log.Println(r, string(debug.Stack()))
			}
		}()

		select {
		case SHUTDOWN <- true:
		default:
			return false
		}

		return true
	})
	return jsonFunc
}

func status() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				log.Println(r, string(debug.Stack()))
			}
		}()

		return true
	})
	return jsonFunc
}

func panicTest() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				log.Println(r, string(debug.Stack()))
			}
		}()

		panic(1)
	})
	return jsonFunc
}

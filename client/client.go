package main

import (
	"lattigo-polls-demo/utils"
	"syscall/js"

	"github.com/ldsec/lattigo/v2/bfv"
)

// PollClient represents a client in the PrivatePoll application
type PollClient struct {
	bfv.KeyGenerator
	bfv.Encoder
	bfv.Encryptor
	bfv.Decryptor

	params *bfv.Parameters
}

// NewPollClient creates a new client instance from the cryptographic parameters and a secret- or public-key.
// A client pointer can perform decryption only if it was instantiated with a secret-key.
func NewPollClient(params *bfv.Parameters, keyObj js.Value) *PollClient {
	pc := new(PollClient)
	pc.params = params
	pc.KeyGenerator = bfv.NewKeyGenerator(params)
	pc.Encoder = bfv.NewEncoder(params)

	switch keyObj.Get("type").String() {
	case "sk":
		sk := bfv.NewSecretKey(params)
		utils.UnmarshalFromBase64(sk, keyObj.Get("key").String())
		pc.Encryptor = bfv.NewEncryptorFromSk(params, sk)
		pc.Decryptor = bfv.NewDecryptor(params, sk)
	case "pk":
		pk := bfv.NewPublicKey(params)
		utils.UnmarshalFromBase64(pk, keyObj.Get("key").String())
		pc.Encryptor = bfv.NewEncryptorFromPk(params, pk)
	}

	return pc
}

func main() {

	var pollClient *PollClient
	var params = bfv.DefaultParams[1]

	// creates the initialization javascript function
	initClientFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		keyObj := args[0]
		pollClient = NewPollClient(params, keyObj)
		return nil
	})
	js.Global().Set("initClient", initClientFunc)

	// creates key generation javascript function
	genKeysFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		jsObj := args[0]
		// generates the necessary keys
		sk, pk := pollClient.GenKeyPair()
		rlk := pollClient.GenRelinKey(sk, 1)

		// exports the keys to js in base64 representation
		jsObj.Set("sk", utils.MarshalToBase64String(sk))
		jsObj.Set("pk", utils.MarshalToBase64String(pk))
		jsObj.Set("rlk", utils.MarshalToBase64String(rlk))

		return jsObj
	})
	js.Global().Set("genKeys", genKeysFunc)

	// creates the encryption javasript function
	encryptFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {

		// extracts the availabilities from the js array.
		coeffs := make([]int64, 7)
		for i := range coeffs {
			coeffs[i] = int64(args[0].Index(i).Int())
		}

		// encodes the inputs in a lattigo plaintext
		pt := bfv.NewPlaintext(params)
		pollClient.EncodeInt(coeffs, pt)

		// encrypts the inputs
		ct := pollClient.EncryptNew(pt)

		return utils.MarshalToBase64String(ct)
	})
	js.Global().Set("encrypt", encryptFunc)

	// creates the decryption javascript function
	decryptFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		ctObj := args[0]

		if pollClient.Decryptor != nil {
			// decrypts the passed ciphertext result into a lattigo plaintext
			ct := bfv.NewCiphertext(params, 1)
			utils.UnmarshalFromBase64(ct, ctObj.String())
			pt := pollClient.DecryptNew(ct)

			coeffs := make([]interface{}, 7)
			for i, v := range pollClient.DecodeIntNew(pt)[:7] {
				coeffs[i] = v
			}
			return coeffs
		}

		return nil
	})
	js.Global().Set("decrypt", decryptFunc)

	<-make(chan bool) // prevents the program from exiting
}

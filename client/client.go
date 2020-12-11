package main

import (
	"lattigo-polls-demo/utils"
	"log"
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
func NewPollClient(params *bfv.Parameters, keyObj js.Value) (*PollClient, error) {
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

	return pc, nil
}

func main() {

	var pollClient *PollClient
	var params = bfv.DefaultParams[1]

	// creates the initialization javascript function
	initClientFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		keyObj := args[0]
		var err error
		if pollClient, err = NewPollClient(params, keyObj); err != nil {
			log.Fatalln("PollClient not initialized:", err)
		}
		log.Println("PollClient initialized")
		return nil
	})

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

	// creates the encryption javasript function
	encryptAvailabilitiesFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		coeffs := JsInputs(args[0])

		// encodes the inputs in a lattigo plaintext
		pt := bfv.NewPlaintext(params)
		pollClient.EncodeInt(coeffs, pt)

		// encrypts the inputs
		ct := pollClient.EncryptNew(pt)

		return utils.MarshalToBase64String(ct)
	})

	// creates the decryption javascript function
	decryptResultsFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		ctObj := args[0]

		if pollClient.Decryptor != nil {
			// decrypts the passed ciphertext result into a lattigo plaintext
			ct := bfv.NewCiphertext(params, 1)
			utils.UnmarshalFromBase64(ct, ctObj.String())
			pt := pollClient.DecryptNew(ct)
			output := pollClient.DecodeIntNew(pt)
			return JsOutput(output[:7])
		}

		return nil
	})

	// register the javascript functions to the global javascript namespace
	js.Global().Set("initClient", initClientFunc)
	js.Global().Set("genKeys", genKeysFunc)
	js.Global().Set("encryptAvailabilities", encryptAvailabilitiesFunc)
	js.Global().Set("decryptResults", decryptResultsFunc)

	<-make(chan bool) // prevents the program from exiting
}

// JsInputs performs the js.Value unwrapping to int64
func JsInputs(in js.Value) []int64 {
	coeffs := make([]int64, 7)
	for i := range coeffs {
		coeffs[i] = int64(in.Index(i).Int())
	}
	return coeffs
}

// JsOutput converts the output to []interface{} to comply with syscall/js return value support
func JsOutput(out []int64) []interface{} {
	coeffs := make([]interface{}, 7)
	for i, v := range out {
		coeffs[i] = v
	}
	return coeffs
}

package utils

import (
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"fmt"
	"reflect"
	"syscall/js"
)

// MarshalToBase64String returns serialization of a marshallable type as a base-64-encoded string
func MarshalToBase64String(bm encoding.BinaryMarshaler) string {
	if bm == nil || reflect.ValueOf(bm).IsNil() {
		return "nil"
	}
	b, err := bm.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// UnmarshalFromBase64 reads a base-64 string into a unmarshallable type
func UnmarshalFromBase64(bum encoding.BinaryUnmarshaler, b64string string) error {
	b, err := base64.StdEncoding.DecodeString(b64string)
	if err != nil {
		return err
	}
	return bum.UnmarshalBinary(b)
}

// GetSha256Hex returns an hexadecimal string representation of the Sha256 hash of marshallable type
func GetSha256Hex(bm encoding.BinaryMarshaler) string {
	b, _ := bm.MarshalBinary()
	return fmt.Sprintf("%x", sha256.Sum256(b))
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

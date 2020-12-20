package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"unicode/utf8"
)

const sighex = "3045022055a047f8c234a208bbf14b3c07c568401250903b699638741df73282bb93835e02210091d316d5607f5200fcd85f9130033f765e15e642352694b6f38956a365870c6c"
const AuthenticatorDatahex = "c7cda80d1930d8b3dcec48417c03167ff949b94019651adee84d04deb96b4a730100000002"
const ClientDataJSONhex = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22587a5f794a4a355478346b4d444169426278714267465039526171362d506550377262675873724a7a3430222c226f726967696e223a2268747470733a2f2f776562617574686e2e6e65746c6966792e617070222c2263726f73734f726967696e223a66616c73657d"

var RealRPID = []byte("webauthn.netlify.app")
var RealRPIDHashArr = sha256.Sum256(RealRPID)
var RealRPIDHash = RealRPIDHashArr[:]

func main() {
	verifyResult, Newcount := verify(
		RealRPID,
		1,
		"5f3ff2249e53c7890c0c08816f1a818053fd45aabaf8f78feeb6e05ecac9cf8d",
		"8ddc560b5dcc09ee253b25ec6c71a803737e0f3bfcba45fbc0555827cbbd25fe",
		"74c8198ec911087d8f87301ee597b1c18ba6cb06a2939138882e2e27d4948a65",
		AuthenticatorDatahex,
		ClientDataJSONhex,
		sighex,
	)
	fmt.Println(verifyResult, Newcount)
}

type ClientDataJSONType struct {
	Type        string
	Challenge   string
	Origin      string
	CrossOrigin bool
}

func verify(RPID []byte, PrevSignCount int, Challenge, PubX, PubY, AuthData, ClientJSON, signature string) (IsVaild bool, RealSignCount int) {
	var X, Y big.Int
	X.SetString(PubX, 16)
	Y.SetString(PubY, 16)
	pubkey := ecdsa.PublicKey{Curve: elliptic.P256(), X: &X, Y: &Y}
	VerifySuccess := elliptic.P256().IsOnCurve(&X, &Y)
	fmt.Println("Is PublicKey Vaild? :", VerifySuccess)
	if !VerifySuccess {
		return false, PrevSignCount
	}
	sig, err := hex.DecodeString(sighex)
	if err != nil {
		return false, PrevSignCount
	}
	AuthenticatorData, err := hex.DecodeString(AuthData)
	if err != nil {
		return false, PrevSignCount
	}
	ClientDataJSON, err := hex.DecodeString(ClientJSON)
	if err != nil {
		return false, PrevSignCount
	}

	VerifySuccess = len(AuthenticatorData) >= 37
	fmt.Println("Is AuthenticatorData Length Vaild? :", VerifySuccess)
	if !VerifySuccess {
		return false, PrevSignCount
	}

	VerifySuccess = utf8.Valid(ClientDataJSON)
	fmt.Println("Is JSON UTF-8 Vaild? :", VerifySuccess)
	if !VerifySuccess {
		return false, PrevSignCount
	}

	VerifySuccess = json.Valid(ClientDataJSON)
	fmt.Println("Is JSON syntax Vaild? :", VerifySuccess)
	if !VerifySuccess {
		return false, PrevSignCount
	}

	var DataJSON ClientDataJSONType
	err = json.Unmarshal(ClientDataJSON, &DataJSON)
	fmt.Println("Is JSON Structure Vaild? :", err == nil)
	if err != nil {
		return false, PrevSignCount
	}

	VerifySuccess = DataJSON.Type == "webauthn.get"
	fmt.Println("Is Response Type Vaild? :", VerifySuccess)
	if !VerifySuccess {
		return false, PrevSignCount
	}

	AuthChallenge, err := base64.RawURLEncoding.DecodeString(DataJSON.Challenge)
	VerifySuccess = err == nil
	fmt.Println("Is Challenge Base64 Vaild? :", VerifySuccess)
	if !VerifySuccess {
		return false, PrevSignCount
	}

	RealChallenge, err := hex.DecodeString(Challenge)
	if err != nil {
		return false, PrevSignCount
	}
	VerifySuccess = bytes.Equal(AuthChallenge, RealChallenge)
	fmt.Println("Is Challenge Equal? :", VerifySuccess)
	if !VerifySuccess {
		return false, PrevSignCount
	}

	RPIDHash := AuthenticatorData[:32]
	SignCount := AuthenticatorData[33:37]

	hash256 := sha256.New()
	hash256.Write(RPID)
	VerifySuccess = bytes.Equal(RPIDHash, hash256.Sum(nil))
	fmt.Println("Is RPID Equal? :", VerifySuccess)
	if !VerifySuccess {
		return false, PrevSignCount
	}

	cDataHash := sha256.Sum256(ClientDataJSON)
	MainHash := append(AuthenticatorData, cDataHash[:]...)
	sigData := sha256.Sum256(MainHash)
	SigVaild := ecdsa.VerifyASN1(&pubkey, sigData[:], sig)
	fmt.Println("Is Signature Vaild? :", SigVaild)
	if !SigVaild {
		return false, PrevSignCount
	}

	AuthSignCount := int(binary.BigEndian.Uint32(SignCount))
	//fmt.Println("SignCount :", AuthSignCount)
	VerifySuccess = AuthSignCount > PrevSignCount
	fmt.Println("Is Not a Replay Attack? :", VerifySuccess)
	if !VerifySuccess {
		return false, PrevSignCount
	}
	//fmt.Println(DataJSON)
	return true, AuthSignCount
}

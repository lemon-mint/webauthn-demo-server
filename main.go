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

const sighex = "3045022100cc44c4581ac0c883e57ab93e793d15ddc07a01171c93a6274801dc4681d31e2902204741fa153289a73b4703e1d4450132e9b1d59b7261c306221a46daa16d7f346b"
const AuthenticatorDatahex = "568147b87f96840205f3bea7b974e678fcf904b2d08c87c5ab323afeadd785a70100000002"
const ClientDataJSONhex = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22587a5f794a4a355478346b4d444169426278714267465039526171362d506550377262675873724a7a3430222c226f726967696e223a2268747470733a2f2f6669646f3264656d6f2e6e65746c6966792e617070222c2263726f73734f726967696e223a66616c73657d"

var RealRPID = []byte("fido2demo.netlify.app")
var RealRPIDHashArr = sha256.Sum256(RealRPID)
var RealRPIDHash = RealRPIDHashArr[:]

func main() {
	verifyResult, Newcount := verify(
		RealRPID,
		1,
		"5f3ff2249e53c7890c0c08816f1a818053fd45aabaf8f78feeb6e05ecac9cf8d",
		"9e7592e341f083e7d53dffe2d0b37c3837c8c8f783b72f48997781bfeec15175",
		"061e64b97d8299ca795fd492d07b87ed0d79a92e29642dad6c106caf4c99bd60",
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

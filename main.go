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
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/akyoto/cache"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"golang.org/x/crypto/acme/autocert"
)

type authChallenge struct {
	UserName   string
	AuthData   string
	Clientjson string
	Signature  string
	SessionID  string
}

type credential struct {
	UserName string
	Pubx     string
	Puby     string
	ID       string
	counter  int
}

type session struct {
	SessionID string
	ID        string
	UserName  string
	Challenge string
}

func main() {
	store := cache.New(time.Hour * 1)
	sessions := cache.New(time.Minute * 5)
	e := echo.New()
	e.AutoTLSManager.Cache = autocert.DirCache("../.tlscache")
	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Root:   "public",
		Browse: false,
	}))
	e.POST("/verify", func(c echo.Context) error {
		Challenge := authChallenge{}
		request := c.Request()
		body, err := ioutil.ReadAll(request.Body)
		//fmt.Println(string(body))
		if err != nil {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		err = json.Unmarshal(body, &Challenge)
		if err != nil {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		v, exists := store.Get(Challenge.UserName)
		if exists {
			CurSession, exists := sessions.Get(Challenge.SessionID)
			if exists && CurSession.(session).UserName == v.(credential).UserName {
				Credential := v.(credential)
				Isvaild, newcount := verify(
					[]byte(request.Host),
					Credential.counter,
					CurSession.(session).Challenge,
					Credential.Pubx,
					Credential.Puby,
					Challenge.AuthData,
					Challenge.Clientjson,
					Challenge.Signature,
				)
				if Isvaild {
					Credential.counter = newcount
					store.Set(Challenge.UserName, Credential, 0)
					return c.String(http.StatusOK, "OK Done")
				}
			}
			return c.String(http.StatusNotAcceptable, "Not Acceptable")
		}
		return c.String(http.StatusNotAcceptable, "Not Acceptable")
	})

	e.POST("/credential", func(c echo.Context) error {
		newCredential := credential{}
		request := c.Request()
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		err = json.Unmarshal(body, &newCredential)
		if err != nil {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		_, exists := store.Get(newCredential.UserName)
		if exists {
			return c.String(http.StatusConflict, "StatusConflict")
		}
		newCredential.counter = 1
		store.Set(newCredential.UserName, newCredential, time.Hour*1)
		return c.String(http.StatusOK, "OK")
	})

	e.POST("/session", func(c echo.Context) error {
		request := c.Request()
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		type UsernameJSON struct {
			UserName string
		}
		uname := UsernameJSON{}
		err = json.Unmarshal(body, &uname)
		if err != nil {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		username := uname.UserName
		NewChallenge := make([]byte, 16)
		SessionID := make([]byte, 16)
		rand.Read(NewChallenge)
		rand.Read(SessionID)
		data, exists := store.Get(username)
		if !exists {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		userdata := data.(credential)
		NewSession := session{}
		NewSession.Challenge = hex.EncodeToString(NewChallenge)
		NewSession.SessionID = hex.EncodeToString(SessionID)
		NewSession.UserName = username
		NewSession.ID = userdata.ID
		sessions.Set(NewSession.SessionID, NewSession, 0)
		return c.JSON(http.StatusOK, NewSession)
	})

	e.Logger.Info(e.StartAutoTLS(":1323"))
}

//ClientDataJSONType JSON
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
	sig, err := hex.DecodeString(signature)
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
	SignCount := AuthenticatorData[33:37]

	RPIDHash := AuthenticatorData[:32]

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

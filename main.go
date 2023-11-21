package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/foehammer127/protoauth/tokens"
	"google.golang.org/protobuf/proto"
)

func main() {
	// Initial Token Object, (With Claims, like JWT)
	t := &tokens.Token{
		Userid:    "12344",
		NotBefore: 1,
		NotAfter:  2,
		Claim:     "1234",
	}

	fmt.Println("Initial Userid", t.GetUserid())

	// First Marshalled Obj
	b, err := proto.Marshal(t)
	if err != nil {
		panic(err)
	}

	public, private, err := GetKeys()
	if err != nil {
		panic(err)
	}

	sig := ed25519.Sign(private, b)

	t2 := &tokens.SignedToken{
		Signature: sig,
		Token:     b,
	}

	fmt.Println("Marshalled And Signed #1", t2)

	b2, err := proto.Marshal(t2)
	if err != nil {
		panic(err)
	}

	fmt.Println("Marshalled, Signed, And Marshalled", b2)

	var t3 tokens.SignedToken
	err = proto.Unmarshal(b2, &t3)
	if err != nil {
		panic(err)
	}

	real := ed25519.Verify(public, t3.Token, t2.Signature)

	fmt.Println("Token Sig Verified", real)

	var t4 tokens.Token
	err = proto.Unmarshal(t3.Token, &t4)
	if err != nil {
		panic(err)
	}

	fmt.Println("Final Token Userid", t4.GetUserid())
}

func GetKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

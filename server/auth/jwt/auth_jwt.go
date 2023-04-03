// Package jwt implements JWT authentication.
package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/tinode/chat/server/auth"
	"github.com/tinode/chat/server/store"
	"github.com/tinode/chat/server/store/types"

	"github.com/golang-jwt/jwt"
)

// authenticator is a singleton instance of the authenticator.
type authenticator struct {
	name      string
	publicKey *rsa.PublicKey
}

// Init initializes the authenticator: parses the config and sets salt, serial number and lifetime.
func (ta *authenticator) Init(jsonconf json.RawMessage, name string) error {
	if name == "" {
		return errors.New("auth_jwt: authenticator name cannot be blank")
	}

	if ta.name != "" {
		return errors.New("auth_jwt: already initialized as " + ta.name + "; " + name)
	}

	ta.name = name

	publicKey, err := os.ReadFile("cert/public.key")
	if err != nil {
		log.Fatalln(err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		log.Fatalln(err)
	}

	ta.publicKey = key

	return nil
}

// IsInitialized returns true if the handler is initialized.
func (ta *authenticator) IsInitialized() bool {
	return ta.name != ""
}

// AddRecord is not supported, will produce an error.
func (authenticator) AddRecord(rec *auth.Rec, secret []byte, remoteAddr string) (*auth.Rec, error) {
	return nil, types.ErrUnsupported
}

// UpdateRecord is not supported, will produce an error.
func (authenticator) UpdateRecord(rec *auth.Rec, secret []byte, remoteAddr string) (*auth.Rec, error) {
	return nil, types.ErrUnsupported
}

// Authenticate checks validity of provided JWT token.
func (ta *authenticator) Authenticate(data []byte, remoteAddr string) (*auth.Rec, []byte, error) {
	var token = string(data)

	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return ta.publicKey, nil
	})

	if err != nil {
		return nil, nil, types.ErrFailed
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, nil, types.ErrFailed
	}

	// Get user id from JWT subject.
	sub := claims["sub"].(string)
	userId, err := strconv.ParseInt(sub, 10, 64)
	if err != nil {
		return nil, nil, types.ErrFailed
	}

	// Check token expiration time.
	exp := claims["exp"].(float64)
	expires := time.Unix(int64(exp), 0).UTC()
	if expires.Before(time.Now().Add(1 * time.Second)) {
		return nil, nil, types.ErrExpired
	}

	uid := store.EncodeUid(userId)

	user, err := store.Users.Get(uid)
	if err != nil {
		return nil, nil, err
	}

	if user == nil {
		// Automatically create user using the attributes stored in JWT Claims.
		user := types.User{
			State: types.StateOK,
			Access: types.DefaultAccess{
				Auth: types.ModeCAuth,
				Anon: types.ModeNone,
			},
			Trusted: map[string]interface{}{"verified": true},
			Public:  map[string]interface{}{"fn": claims["name"].(string)},
			Tags:    []string{"basic:" + claims["username"].(string)},
		}

		user.SetUid(uid)
		user.InitTimes()

		_, err = store.Users.Create(&user, nil)
		if err != nil {
			return nil, nil, err
		}

		// Add email as a credential.
		email := claims["email"].(string)
		if email != "" {
			if _, err := store.Users.UpsertCred(&types.Credential{
				User:   user.Id,
				Method: "email",
				Value:  email,
				Done:   true,
			}); err != nil {
				log.Fatal(err)
			}
		}
	}

	return &auth.Rec{
		Uid:       uid,
		AuthLevel: auth.LevelAuth,
		Features:  auth.FeatureValidated,
		State:     types.StateOK,
	}, nil, nil
}

// GenSecret generates a new token. Always fails.
func (ta *authenticator) GenSecret(rec *auth.Rec) ([]byte, time.Time, error) {
	return nil, time.Time{}, types.ErrUnsupported
}

// AsTag is not supported, will produce an empty string.
func (authenticator) AsTag(token string) string {
	return ""
}

// IsUnique is not supported, will produce an error.
func (authenticator) IsUnique(token []byte, remoteAddr string) (bool, error) {
	return false, types.ErrUnsupported
}

// DelRecords adds disabled user ID to a stop list.
func (authenticator) DelRecords(uid types.Uid) error {
	return nil
}

// RestrictedTags returns tag namespaces restricted by this authenticator (none for token).
func (authenticator) RestrictedTags() ([]string, error) {
	return nil, nil
}

// GetResetParams returns authenticator parameters passed to password reset handler
// (none for token).
func (authenticator) GetResetParams(uid types.Uid) (map[string]interface{}, error) {
	return nil, nil
}

const realName = "jwt"

// GetRealName returns the hardcoded name of the authenticator.
func (authenticator) GetRealName() string {
	return realName
}

func init() {
	store.RegisterAuthScheme(realName, &authenticator{})
}

package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	cfg "github.com/slotopol/server/config"
	"github.com/slotopol/server/util"
)

const (
	// "iss" field for this tokens.
	jwtIssuer = "slotopol"

	// Pointer to User object stored at gin context
	// after successful authorization.
	userKey = "user"

	realmBasic  = `Basic realm="slotopol", charset="UTF-8"`
	realmBearer = `JWT realm="slotopol", charset="UTF-8"`
)

const (
	sqlnewprops = `INSERT INTO props (cid,uid) SELECT cid,? FROM club`
)

var (
	ErrNoJwtID  = errors.New("jwt-token does not have user id")
	ErrBadJwtID = errors.New("jwt-token id does not refer to registered user")
	ErrNoAuth   = errors.New("authorization is required")
	ErrNoScheme = errors.New("authorization does not have expected scheme")
	ErrNoSecret = errors.New("expected password or SHA256 hash on it and current time as a nonce")
	ErrSmallKey = errors.New("password too small")
	ErrNoCred   = errors.New("user with given credentials does not registered")
	ErrActivate = errors.New("activation required for this account")
	ErrOldCode  = errors.New("verification code expired")
	ErrBadCode  = errors.New("verification code does not pass")
	ErrNotPass  = errors.New("password is incorrect")
	ErrSigTime  = errors.New("signing time can not been recognized (time in RFC3339 expected)")
	ErrSigOut   = errors.New("nonce is expired")
	ErrBadHash  = errors.New("hash cannot be decoded in hexadecimal")
)

var (
	Cfg = cfg.Cfg
)

// Claims of JWT-tokens. Contains additional profile identifier.
type Claims struct {
	jwt.RegisteredClaims
	UID uint64 `json:"uid,omitempty"`
}

func (c *Claims) Validate() error {
	if c.UID == 0 {
		return ErrNoJwtID
	}
	return nil
}

type AuthGetter func(c *gin.Context) (*User, int, error)

// AuthGetters is the list of functions to extract the authorization
// data from the parts of request. List and order in it can be changed.
var AuthGetters = []AuthGetter{
	UserFromHeader, UserFromQuery, UserFromCookie,
}

// Auth is authorization middleware, sets User object associated
// with authorization to gin context. `required` parameter tells
// to continue if authorization is absent.
func Auth(required bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		var code int
		var user *User
		for _, getter := range AuthGetters {
			if user, code, err = getter(c); err != nil {
				Ret401(c, code, err)
				return
			}
			if user != nil {
				break
			}
		}

		if user != nil {
			c.Set(userKey, user)
		} else if required {
			Ret401(c, AEC_auth_absent, ErrNoAuth)
			return
		}

		c.Next()
	}
}

func UserFromHeader(c *gin.Context) (*User, int, error) {
	if hdr := c.Request.Header.Get("Authorization"); hdr != "" {
		if strings.HasPrefix(hdr, "Basic ") {
			return GetBasicAuth(hdr[6:])
		} else if strings.HasPrefix(hdr, "Bearer ") {
			return GetBearerAuth(hdr[7:])
		} else {
			return nil, AEC_auth_scheme, ErrNoScheme
		}
	}
	return nil, 0, nil
}

func UserFromQuery(c *gin.Context) (*User, int, error) {
	if credentials := c.Query("cred"); credentials != "" {
		return GetBasicAuth(credentials)
	} else if tokenstr := c.Query("token"); tokenstr != "" {
		return GetBearerAuth(tokenstr)
	} else if tokenstr := c.Query("jwt"); tokenstr != "" {
		return GetBearerAuth(tokenstr)
	}
	return nil, 0, nil
}

func UserFromCookie(c *gin.Context) (*User, int, error) {
	if credentials, _ := c.Cookie("cred"); credentials != "" {
		return GetBasicAuth(credentials)
	} else if tokenstr, _ := c.Cookie("token"); tokenstr != "" {
		return GetBearerAuth(tokenstr)
	} else if tokenstr, _ := c.Cookie("jwt"); tokenstr != "" {
		return GetBearerAuth(tokenstr)
	}
	return nil, 0, nil
}

func UserFromForm(c *gin.Context) (*User, int, error) {
	if credentials := c.PostForm("cred"); credentials != "" {
		return GetBasicAuth(credentials)
	} else if tokenstr := c.PostForm("token"); tokenstr != "" {
		return GetBearerAuth(tokenstr)
	} else if tokenstr := c.PostForm("jwt"); tokenstr != "" {
		return GetBearerAuth(tokenstr)
	}
	return nil, 0, nil
}

func GetBasicAuth(credentials string) (user *User, code int, err error) {
	var decoded []byte
	if decoded, err = base64.RawURLEncoding.DecodeString(credentials); err != nil {
		return nil, AEC_basic_decode, err
	}
	var parts = strings.Split(util.B2S(decoded), ":")

	var email = util.ToLower(parts[0])
	for _, u := range Users.Items() {
		if u.Email == email {
			user = u
			break
		}
	}
	if user == nil {
		err, code = ErrNoCred, AEC_basic_nouser
		return
	}
	if user.Secret != parts[1] {
		err, code = ErrNotPass, AEC_basic_deny
		return
	}
	return
}

func GetBearerAuth(tokenstr string) (user *User, code int, err error) {
	var claims Claims
	_, err = jwt.ParseWithClaims(tokenstr, &claims, func(*jwt.Token) (any, error) {
		var keys = jwt.VerificationKeySet{
			Keys: []jwt.VerificationKey{
				util.S2B(Cfg.AccessKey),
				util.S2B(Cfg.RefreshKey),
			},
		}
		return keys, nil
	}, jwt.WithExpirationRequired(), jwt.WithIssuer(jwtIssuer), jwt.WithLeeway(5*time.Second))

	if err == nil {
		var ok bool
		if user, ok = Users.Get(claims.UID); !ok {
			err, code = ErrBadJwtID, AEC_token_nouser
		}
		return
	}
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		code = AEC_token_malform
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		code = AEC_token_notsign
	case errors.Is(err, jwt.ErrTokenInvalidClaims):
		code = AEC_token_badclaims
	case errors.Is(err, jwt.ErrTokenExpired):
		code = AEC_token_expired
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		code = AEC_token_notyet
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		code = AEC_token_issuer
	default:
		code = AEC_token_error
	}
	return
}

func Handle404(c *gin.Context) {
	Ret404(c, AEC_nourl, Err404)
}

func Handle405(c *gin.Context) {
	RetErr(c, http.StatusMethodNotAllowed, AEC_nomethod, Err405)
}

type AuthResp struct {
	XMLName xml.Name `json:"-" yaml:"-" xml:"ret"`
	UID     uint64   `json:"uid" yaml:"uid" xml:"uid"`
	Email   string   `json:"email" yaml:"email" xml:"email"`
	Access  string   `json:"access" yaml:"access" xml:"access"`
	Refrsh  string   `json:"refrsh" yaml:"refrsh" xml:"refrsh"`
	Expire  string   `json:"expire" yaml:"expire" xml:"expire"`
	Living  string   `json:"living" yaml:"living" xml:"living"`
}

func (r *AuthResp) Setup(user *User) {
	var err error
	var token *jwt.Token
	var now = jwt.NewNumericDate(time.Now())
	var exp = jwt.NewNumericDate(time.Now().Add(Cfg.AccessTTL))
	var age = jwt.NewNumericDate(time.Now().Add(Cfg.RefreshTTL))
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			NotBefore: now,
			ExpiresAt: exp,
			Issuer:    jwtIssuer,
		},
		UID: user.UID,
	})
	if r.Access, err = token.SignedString([]byte(Cfg.AccessKey)); err != nil {
		panic(err)
	}
	r.Expire = exp.Format(time.RFC3339)
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			NotBefore: now,
			ExpiresAt: age,
			Issuer:    jwtIssuer,
		},
		UID: user.UID,
	})
	if r.Refrsh, err = token.SignedString([]byte(Cfg.AccessKey)); err != nil {
		panic(err)
	}
	r.Living = age.Format(time.RFC3339)
	r.UID = user.UID
	r.Email = user.Email
}

func sendcode(name, email string, code uint32) (err error) {
	type person struct {
		Name  string `json:"name,omitempty"`
		Email string `json:"email"`
	}
	type content struct {
		Sender  person   `json:"sender"`
		ReplyTo person   `json:"replyTo"`
		To      []person `json:"to"`
		Subject string   `json:"subject,omitempty"`
		Html    string   `json:"htmlContent,omitempty"`
		Text    string   `json:"textContent,omitempty"`
		Tags    []string `json:"tags,omitempty"`
	}

	const ct = "application/json"
	var m = content{
		Sender: person{
			Name:  Cfg.SenderName,
			Email: Cfg.SenderEmail,
		},
		ReplyTo: person{
			Email: Cfg.ReplytoEmail,
		},
		To: []person{
			{
				Name:  name,
				Email: email,
			},
		},
		Subject: Cfg.EmailSubject,
		Html:    fmt.Sprintf(Cfg.EmailHtmlContent, code),
	}

	var body []byte
	if body, err = json.Marshal(m); err != nil {
		return err
	}

	var req *http.Request
	if req, err = http.NewRequest("POST", Cfg.BrevoEmailEndpoint, bytes.NewReader(body)); err != nil {
		return err
	}
	req.Header.Set("api-key", Cfg.BrevoApiKey)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Accept", ct)

	var resp *http.Response
	if resp, err = http.DefaultClient.Do(req); err != nil {
		return err
	}
	defer resp.Body.Close()

	if body, err = io.ReadAll(resp.Body); err != nil {
		return err
	}
	var rm map[string]string
	if err = json.Unmarshal(body, &rm); err != nil {
		return err
	}
	if msg, ok := rm["message"]; ok {
		return errors.New(msg)
	}
	return
}

// Assign user to a club and update properties
func assignUserToClubs(user *User) error {
	for _, club := range Clubs.Items() {
		user.InsertProps(&Props{
			CID: club.CID(),
			UID: user.UID,
		})
	}
	return nil
}
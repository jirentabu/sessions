package sessions

import (
	"bytes"
	"encoding/base32"
	"encoding/gob"
	"github.com/boj/redistore"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"net/http"
	"strings"
)

// RedisStore is an interface that represents a Cookie based storage
// for Sessions.
type RediStore interface {
	// Store is an embedded interface so that RedisStore can be used
	// as a session store.
	Store
	// Options sets the default options for each session stored in this
	// CookieStore.
	Options(Options)
}

// NewCookieStore returns a new CookieStore.
//
// Keys are defined in pairs to allow key rotation, but the common case is to set a single
// authentication key and optionally an encryption key.
//
// The first key in a pair is used for authentication and the second for encryption. The
// encryption key can be set to nil or omitted in the last pair, but the authentication key
// is required in all pairs.
//
// It is recommended to use an authentication key with 32 or 64 bytes. The encryption key,
// if set, must be either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256 modes.
func NewRediStore(size int, network, address, password string, keyPairs ...[]byte) (RediStore, error) {
	store, err := redistore.NewRediStore(size, network, address, password, keyPairs...)
	if err != nil {
		return nil, err
	}
	return &rediStore{store}, nil
}

type rediStore struct {
	*redistore.RediStore
}

func (c *rediStore) Options(options Options) {
	c.RediStore.Options = &sessions.Options{
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
	}
}

// New returns a session for the given name without adding it to the registry.
//
// See gorilla/sessions FilesystemStore.New().
func (s *rediStore) New(r *http.Request, name string) (*sessions.Session, error) {
	var err error
	session := sessions.NewSession(s, name)
	// make a copy
	options := *s.RediStore.Options
	session.Options = &options
	session.IsNew = true

	var token string
	if c, errCookie := r.Cookie(name); errCookie == nil {
		token = c.Value
	} else if v := r.URL.Query().Get(name); v != "" { // fetch from url query
		token = v
	} else if v := r.Header.Get(name); v != "" { // fetch from http header query
		token = v
	}

	// decode id and load session
	if token != "" {
		err = securecookie.DecodeMulti(name, token, &session.ID, s.Codecs...)
		if err == nil {
			ok, err := s.load(session)
			session.IsNew = !(err == nil && ok) // not new if no error and data available
		}
	}
	if session.IsNew {
		session.ID = strings.TrimRight(base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32)), "=")
	}

	return session, err
}

func (s *rediStore) load(session *sessions.Session) (bool, error) {
	conn := s.Pool.Get()
	defer conn.Close()
	if err := conn.Err(); err != nil {
		return false, err
	}
	data, err := conn.Do("GET", "session_"+session.ID)
	if err != nil {
		return false, err
	}
	if data == nil {
		return false, nil // no data was associated with this key
	}
	b, err := redis.Bytes(data, err)
	if err != nil {
		return false, err
	}
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return true, dec.Decode(&session.Values)
}

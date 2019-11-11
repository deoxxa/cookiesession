package cookiesession

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/satori/go.uuid"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	ErrTooShort = errors.New("encoded session data is too short")
)

type Session struct {
	Valid   bool
	Time    time.Time
	SID     uuid.UUID
	UID     uuid.UUID
	RealUID uuid.UUID
	State   []byte
}

func (s *Session) UnmarshalBinary(data []byte) error {
	if len(data) < 8+16+16+16 {
		return ErrTooShort
	}

	sid, err := uuid.FromBytes(data[8:24])
	if err != nil {
		return err
	}

	uid, err := uuid.FromBytes(data[24:40])
	if err != nil {
		return err
	}

	realUID, err := uuid.FromBytes(data[40:56])
	if err != nil {
		return err
	}

	s.Valid = true
	s.Time = time.Unix(int64(binary.BigEndian.Uint64(data)), 0)
	s.SID = sid
	s.UID = uid
	s.RealUID = realUID
	s.State = data[56:]

	return nil
}

func (s *Session) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 8)

	binary.BigEndian.PutUint64(buf, uint64(s.Time.Unix()))
	buf = append(buf, s.SID[:]...)
	buf = append(buf, s.UID[:]...)
	buf = append(buf, s.RealUID[:]...)
	buf = append(buf, s.State...)

	return buf, nil
}

type Store struct {
	Name, Secret     string
	HttpOnly, Secure bool
	TTL              time.Duration
	Key              [32]byte
}

func New(name, secret string, ttl time.Duration) *Store {
	var key [32]byte
	h := sha256.New()
	h.Write([]byte(secret))
	copy(key[:], h.Sum(nil))

	return &Store{
		Name:   name,
		Secret: secret,
		TTL:    ttl,
		Key:    key,
	}
}

func (s *Store) Get(r *http.Request) Session {
	c, err := r.Cookie(s.Name)
	if err != nil {
		return Session{SID: uuid.Must(uuid.NewV4())}
	} else if c == nil {
		return Session{SID: uuid.Must(uuid.NewV4())}
	}

	encrypted, err := base64.StdEncoding.DecodeString(c.Value)
	if err != nil {
		return Session{SID: uuid.Must(uuid.NewV4())}
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	buf, ok := secretbox.Open(nil, encrypted[24:], &nonce, &s.Key)
	if !ok {
		return Session{SID: uuid.Must(uuid.NewV4())}
	}

	var ss Session
	if err := ss.UnmarshalBinary(buf); err != nil {
		return Session{SID: uuid.Must(uuid.NewV4())}
	}

	if time.Now().Sub(ss.Time) > s.TTL {
		return Session{SID: uuid.Must(uuid.NewV4())}
	}

	return ss
}

func (s *Store) Save(rw http.ResponseWriter, ss *Session) error {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return errors.New("couldn't get random nonce: " + err.Error())
	}

	ss.Time = time.Now()

	buf, err := ss.MarshalBinary()
	if err != nil {
		return errors.New("couldn't encode session: " + err.Error())
	}

	http.SetCookie(rw, &http.Cookie{
		Path:     "/",
		HttpOnly: s.HttpOnly,
		Secure:   s.Secure,
		Name:     s.Name,
		Expires:  ss.Time.Add(s.TTL),
		MaxAge:   int(s.TTL / time.Second),
		Value:    base64.StdEncoding.EncodeToString(secretbox.Seal(nonce[:], buf, &nonce, &s.Key)),
	})

	return nil
}

func (s *Store) Clear(rw http.ResponseWriter) {
	http.SetCookie(rw, &http.Cookie{
		Path:     "/",
		HttpOnly: s.HttpOnly,
		Secure:   s.Secure,
		Name:     s.Name,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Value:    "",
	})
}

package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	deviceTTL         = 600 * time.Second
	deviceExpiresIn   = 600
	deviceInterval    = 5 * time.Second
	deviceIntervalSec = 5
	userCodeAttempts  = 5
)

// DeviceCode is the response a client polls with. DeviceCode is plaintext and is not stored.
type DeviceCode struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int
	Interval                int
}

// DeviceToken is a new mcp session. Token is the plaintext bearer, returned once.
type DeviceToken struct {
	Token     string
	ExpiresAt time.Time
}

// DeviceStatus is the console view of a user code.
type DeviceStatus struct {
	UserCode   string
	ClientName string
	Status     string
	ExpiresAt  time.Time
}

type pollRec struct {
	last     time.Time
	interval time.Duration
	seen     bool
	expires  time.Time
}

// StartDevice inserts a device code. The plaintext device code is returned once.
func (s *Service) StartDevice(ctx context.Context, clientName string) (DeviceCode, error) {
	var lastErr error
	for i := 0; i < userCodeAttempts; i++ {
		plain, hash, err := secret.NewToken()
		if err != nil {
			return DeviceCode{}, err
		}
		userCode, err := secret.NewUserCode()
		if err != nil {
			return DeviceCode{}, err
		}
		now := s.now()
		err = s.st.CreateDevice(ctx, store.Device{
			ID:         uuid.New(),
			Hash:       hash,
			UserCode:   userCode,
			ClientName: clientName,
			CreatedAt:  now,
			ExpiresAt:  now.Add(deviceTTL),
		})
		if errors.Is(err, store.ErrConflict) {
			lastErr = err
			continue
		}
		if err != nil {
			return DeviceCode{}, err
		}
		return DeviceCode{
			DeviceCode:              plain,
			UserCode:                userCode,
			VerificationURI:         s.cfg.DeviceVerificationURI,
			VerificationURIComplete: verificationComplete(s.cfg.DeviceVerificationURI, userCode),
			ExpiresIn:               deviceExpiresIn,
			Interval:                deviceIntervalSec,
		}, nil
	}
	if lastErr == nil {
		lastErr = store.ErrConflict
	}
	return DeviceCode{}, lastErr
}

func verificationComplete(uri, userCode string) string {
	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}
	return uri + sep + "code=" + url.QueryEscape(userCode)
}

// NormalizeUserCode uppercases and strips hyphens. A valid code is XXXX-XXXX.
func NormalizeUserCode(raw string) (string, bool) {
	up := strings.ToUpper(strings.ReplaceAll(raw, "-", ""))
	if len(up) != 8 {
		return "", false
	}
	for i := 0; i < len(up); i++ {
		if !strings.ContainsRune(secret.UserCodeAlphabet, rune(up[i])) {
			return "", false
		}
	}
	return up[:4] + "-" + up[4:], true
}

// DeviceStatus reports pending, approved, denied, or expired. Consumed stays approved until expiry.
func (s *Service) DeviceStatus(ctx context.Context, userCode string) (DeviceStatus, error) {
	code, ok := NormalizeUserCode(userCode)
	if !ok {
		return DeviceStatus{}, store.ErrNotFound
	}
	d, err := s.st.DeviceByUserCode(ctx, code)
	if err != nil {
		return DeviceStatus{}, err
	}
	return DeviceStatus{
		UserCode:   d.UserCode,
		ClientName: d.ClientName,
		Status:     deviceStatus(d, s.now()),
		ExpiresAt:  d.ExpiresAt,
	}, nil
}

func deviceStatus(d store.Device, now time.Time) string {
	if !now.Before(d.ExpiresAt) {
		return "expired"
	}
	if d.DeniedAt != nil {
		return "denied"
	}
	if d.ApprovedAt != nil {
		return "approved"
	}
	return "pending"
}

// ApproveDevice marks a pending code approved. Store errors are returned as-is.
func (s *Service) ApproveDevice(ctx context.Context, userCode string, userID uuid.UUID) error {
	code, ok := NormalizeUserCode(userCode)
	if !ok {
		return store.ErrNotFound
	}
	return s.st.ApproveDevice(ctx, code, userID, s.now())
}

// DenyDevice marks a pending code denied. Store errors are returned as-is.
func (s *Service) DenyDevice(ctx context.Context, userCode string, userID uuid.UUID) error {
	code, ok := NormalizeUserCode(userCode)
	if !ok {
		return store.ErrNotFound
	}
	return s.st.DenyDevice(ctx, code, userID, s.now())
}

// PollDevice rate-limits a code that already has a poll record before the
// database lookup. An unknown hash does not create a record. last is updated
// only when the poll is allowed. slow_down does not move last and adds 5s
// to the interval.
func (s *Service) PollDevice(ctx context.Context, deviceCode string) (DeviceToken, error) {
	sum := secret.Hash(deviceCode)
	now := s.now()
	if err := s.throttlePoll(sum, now); err != nil {
		return DeviceToken{}, err
	}
	d, err := s.st.DeviceByHash(ctx, sum)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return DeviceToken{}, ErrExpiredToken
		}
		return DeviceToken{}, err
	}
	if err := s.rememberPoll(sum, d.ExpiresAt, now); err != nil {
		return DeviceToken{}, err
	}
	if !now.Before(d.ExpiresAt) {
		return DeviceToken{}, ErrExpiredToken
	}
	if d.DeniedAt != nil {
		return DeviceToken{}, ErrAccessDenied
	}
	if d.ApprovedAt == nil {
		return DeviceToken{}, ErrPending
	}
	if d.ConsumedAt != nil {
		return DeviceToken{}, ErrExpiredToken
	}
	if s.cfg.MCPResource == "" {
		return DeviceToken{}, errors.New("mcp resource is not configured")
	}
	consumed, err := s.st.ConsumeDevice(ctx, sum, now)
	if err != nil {
		return DeviceToken{}, s.mapConsumeErr(ctx, sum, err)
	}
	plain, hash, err := secret.NewToken()
	if err != nil {
		return DeviceToken{}, err
	}
	exp := now.Add(mcpSessionTTL)
	var userID uuid.UUID
	if consumed.ApprovedBy != nil {
		userID = *consumed.ApprovedBy
	}
	sess, err := s.st.IssueDeviceAccess(ctx, store.IssueDevice{
		UserID:    userID,
		TokenHash: hash,
		Audience:  s.cfg.MCPResource,
		ExpiresAt: exp,
		At:        now,
	})
	if err != nil {
		return DeviceToken{}, err
	}
	return DeviceToken{Token: plain, ExpiresAt: sess.ExpiresAt}, nil
}

func (s *Service) throttlePoll(hash []byte, now time.Time) error {
	key := hex.EncodeToString(hash)
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.polls[key]
	if !ok || !rec.seen {
		return nil
	}
	if now.Sub(rec.last) < rec.interval {
		rec.interval += deviceInterval
		s.polls[key] = rec
		return ErrSlowDown
	}
	rec.last = now
	s.polls[key] = rec
	return nil
}

// rememberPoll stores a poll record only after the device row was found.
// A full map refuses the new code with slow_down and does not insert it.
func (s *Service) rememberPoll(hash []byte, exp, now time.Time) error {
	key := hex.EncodeToString(hash)
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.polls[key]
	if ok && rec.seen {
		rec.expires = exp
		s.polls[key] = rec
		return nil
	}
	if len(s.polls) >= pollCap {
		return ErrSlowDown
	}
	s.polls[key] = pollRec{
		last:     now,
		interval: deviceInterval,
		seen:     true,
		expires:  exp,
	}
	return nil
}

// PurgeDevices deletes device codes that expired more than 24h ago and drops
// poll records for those hashes and for any code already past its expiry.
func (s *Service) PurgeDevices(ctx context.Context) error {
	now := s.now()
	hashes, err := s.st.DeleteExpiredDevices(ctx, now.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, hash := range hashes {
		delete(s.polls, hex.EncodeToString(hash))
	}
	for key, rec := range s.polls {
		if !rec.expires.IsZero() && !now.Before(rec.expires) {
			delete(s.polls, key)
		}
	}
	return nil
}

func (s *Service) mapConsumeErr(ctx context.Context, hash []byte, err error) error {
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExpired) {
		return ErrExpiredToken
	}
	if errors.Is(err, store.ErrState) {
		d, derr := s.st.DeviceByHash(ctx, hash)
		if derr == nil && d.DeniedAt != nil {
			return ErrAccessDenied
		}
		return ErrPending
	}
	return err
}

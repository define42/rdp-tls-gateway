package main

import (
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"strconv"
	"strings"
	"sync"
	"time"
)

const loginRateLimitCleanupInterval = time.Minute

type loginAttemptBucket struct {
	failures    []time.Time
	lockedUntil time.Time
}

type loginRateLimiter struct {
	mu sync.Mutex

	maxAttempts int
	window      time.Duration
	lockout     time.Duration

	attempts    map[string]*loginAttemptBucket
	nextCleanup time.Time
	now         func() time.Time
}

func newLoginRateLimiter(settings *config.SettingsType) *loginRateLimiter {
	limiter := &loginRateLimiter{
		attempts: make(map[string]*loginAttemptBucket),
		now:      time.Now,
	}
	if settings == nil {
		return limiter
	}

	limiter.maxAttempts = settings.GetInt(config.LOGIN_RATE_LIMIT_MAX_ATTEMPTS)
	limiter.window = settings.GetDuration(config.LOGIN_RATE_LIMIT_WINDOW)
	limiter.lockout = settings.GetDuration(config.LOGIN_RATE_LIMIT_LOCKOUT)
	return limiter
}

func (l *loginRateLimiter) enabled() bool {
	return l != nil && l.maxAttempts > 0 && l.window > 0 && l.lockout > 0
}

func (l *loginRateLimiter) RetryAfter(username, remoteAddr string) (time.Duration, bool) {
	if !l.enabled() {
		return 0, false
	}

	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.cleanupExpired(now)

	var retryAfter time.Duration
	for _, key := range loginRateLimitKeys(username, remoteAddr) {
		bucket := l.attempts[key]
		if bucket == nil {
			continue
		}
		l.pruneBucket(bucket, now)
		if retry := bucketRetryAfter(bucket, now); retry > retryAfter {
			retryAfter = retry
		}
	}

	return retryAfter, retryAfter > 0
}

func (l *loginRateLimiter) RecordFailure(username, remoteAddr string) time.Duration {
	if !l.enabled() {
		return 0
	}

	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.cleanupExpired(now)

	var retryAfter time.Duration
	for _, key := range loginRateLimitKeys(username, remoteAddr) {
		bucket := l.bucketForKey(key)
		l.pruneBucket(bucket, now)
		if retry := bucketRetryAfter(bucket, now); retry > retryAfter {
			retryAfter = retry
			continue
		}

		bucket.failures = append(bucket.failures, now)
		if len(bucket.failures) >= l.maxAttempts {
			bucket.failures = nil
			bucket.lockedUntil = now.Add(l.lockout)
			if l.lockout > retryAfter {
				retryAfter = l.lockout
			}
		}
	}

	return retryAfter
}

func (l *loginRateLimiter) RecordSuccess(username, remoteAddr string) {
	if !l.enabled() {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, key := range loginRateLimitKeys(username, remoteAddr) {
		delete(l.attempts, key)
	}
}

func (l *loginRateLimiter) bucketForKey(key string) *loginAttemptBucket {
	bucket := l.attempts[key]
	if bucket == nil {
		bucket = &loginAttemptBucket{}
		l.attempts[key] = bucket
	}
	return bucket
}

func (l *loginRateLimiter) pruneBucket(bucket *loginAttemptBucket, now time.Time) {
	if !bucket.lockedUntil.IsZero() && !now.Before(bucket.lockedUntil) {
		bucket.lockedUntil = time.Time{}
		bucket.failures = nil
		return
	}

	cutoff := now.Add(-l.window)
	failures := bucket.failures[:0]
	for _, failure := range bucket.failures {
		if !failure.Before(cutoff) {
			failures = append(failures, failure)
		}
	}
	bucket.failures = failures
}

func (l *loginRateLimiter) cleanupExpired(now time.Time) {
	if !l.nextCleanup.IsZero() && now.Before(l.nextCleanup) {
		return
	}
	l.nextCleanup = now.Add(loginRateLimitCleanupInterval)

	for key, bucket := range l.attempts {
		l.pruneBucket(bucket, now)
		if len(bucket.failures) == 0 && bucket.lockedUntil.IsZero() {
			delete(l.attempts, key)
		}
	}
}

func bucketRetryAfter(bucket *loginAttemptBucket, now time.Time) time.Duration {
	if bucket == nil || bucket.lockedUntil.IsZero() || !now.Before(bucket.lockedUntil) {
		return 0
	}
	return bucket.lockedUntil.Sub(now)
}

func loginRateLimitKeys(username, remoteAddr string) []string {
	keys := []string{"ip:" + loginRateLimitClientIP(remoteAddr)}
	if userKey := loginRateLimitUsername(username); userKey != "" {
		keys = append(keys, "user:"+userKey)
	}
	return keys
}

func loginRateLimitClientIP(remoteAddr string) string {
	if ip, ok := session.CanonicalClientIP(remoteAddr); ok {
		return ip
	}
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return "unknown"
	}
	return remoteAddr
}

func loginRateLimitUsername(username string) string {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" || len(username) > maxLoginUsernameLength {
		return ""
	}
	return username
}

func loginRetryAfterSeconds(retryAfter time.Duration) string {
	seconds := int((retryAfter + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}

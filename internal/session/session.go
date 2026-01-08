package session

import (
	"context"
	"encoding/gob"
	"net/http"
	"rdptlsgateway/internal/types"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
)

type sessionData struct {
	User      *types.User
	CreatedAt time.Time
}

const sessionKey = "session"

func init() {
	gob.Register(sessionData{})
}

const sessionTTL = 30 * time.Minute

type Manager struct {
	*scs.SessionManager
}

func NewManager() *Manager {
	return &Manager{SessionManager: newSessionManager()}
}

func newSessionManager() *scs.SessionManager {
	manager := scs.New()
	manager.Store = memstore.New()
	manager.Lifetime = sessionTTL
	manager.Cookie.Name = "cv_session"
	manager.Cookie.Path = "/"
	manager.Cookie.HttpOnly = true
	manager.Cookie.SameSite = http.SameSiteLaxMode
	manager.Cookie.Secure = true
	return manager
}

func (m *Manager) CreateSession(ctx context.Context, u *types.User) error {
	if err := m.RenewToken(ctx); err != nil {
		return err
	}
	m.Put(ctx, sessionKey, sessionData{
		User:      u,
		CreatedAt: time.Now(),
	})
	return nil
}

func (m *Manager) getSession(r *http.Request) (sessionData, bool) {
	sess, ok := m.Get(r.Context(), sessionKey).(sessionData)
	if !ok || sess.User == nil {
		return sessionData{}, false
	}
	return sess, true
}

func (m *Manager) UserFromContext(ctx context.Context) (*types.User, bool) {
	if ctx == nil {
		return nil, false
	}
	if sess, ok := m.Get(ctx, sessionKey).(sessionData); ok && sess.User != nil {
		return sess.User, true
	}
	if sess, ok := ctx.Value(sessionContextKey{}).(sessionData); ok && sess.User != nil {
		return sess.User, true
	}
	return nil, false
}

func (m *Manager) GetSessionFromUserName(username string) (sessionData, bool) {
	store, ok := m.Store.(scs.IterableStore)
	if !ok {
		return sessionData{}, false
	}
	sessions, err := store.All()
	if err != nil {
		return sessionData{}, false
	}
	for _, raw := range sessions {
		_, values, err := m.Codec.Decode(raw)
		if err != nil {
			continue
		}
		if sess, ok := values[sessionKey].(sessionData); ok &&
			sess.User != nil && sess.User.GetName() == username {
			return sess, true
		}
	}
	return sessionData{}, false
}

func (m *Manager) DestroySession(ctx context.Context) error {
	return m.Destroy(ctx)
}

type sessionContextKey struct{}

func (m *Manager) SessionMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		req, w := humachi.Unwrap(ctx)

		sess, ok := m.getSession(req)
		if !ok || sess.User == nil {
			http.Redirect(w, req, "/login", http.StatusSeeOther)
			return
		}

		next(huma.WithValue(ctx, sessionContextKey{}, sess))
	}
}

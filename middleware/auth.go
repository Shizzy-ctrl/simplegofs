package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"simplegofs/repositories"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Session represents an active user session
type Session struct {
	Username  string
	IsAdmin   bool
	ExpiresAt time.Time
}

var (
	sessions  = make(map[string]*Session)
	sessionMu sync.RWMutex
)

const sessionCookieName = "session_token"

// GenerateSessionToken creates a random session token
func GenerateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// CreateSession creates a new session and returns the token
func CreateSession(username string, isAdmin bool) string {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	token := GenerateSessionToken()
	sessions[token] = &Session{
		Username:  username,
		IsAdmin:   isAdmin,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	return token
}

// GetSession retrieves a session by token
func GetSession(token string) (*Session, bool) {
	sessionMu.RLock()
	defer sessionMu.RUnlock()

	session, exists := sessions[token]
	if !exists || time.Now().After(session.ExpiresAt) {
		return nil, false
	}
	return session, true
}

// DeleteSession removes a session
func DeleteSession(token string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	delete(sessions, token)
}

// RequireAuth middleware ensures user is authenticated
func RequireAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Cookies(sessionCookieName)
		if token == "" {
			return c.Redirect("/login")
		}

		session, valid := GetSession(token)
		if !valid {
			return c.Redirect("/login")
		}

		// Store session info in context
		c.Locals("username", session.Username)
		c.Locals("isAdmin", session.IsAdmin)

		return c.Next()
	}
}

// RequireAdmin middleware ensures user is an admin
func RequireAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		isAdmin, ok := c.Locals("isAdmin").(bool)
		if !ok || !isAdmin {
			return c.Status(fiber.StatusForbidden).SendString("Admin access required")
		}
		return c.Next()
	}
}

// CanAccessFile checks if user can access a file
func CanAccessFile(username, filename string, isAdmin bool, permRepo *repositories.PermissionRepository) bool {
	if isAdmin {
		return true
	}

	canAccess, err := permRepo.CanUserAccessFile(username, filename)
	if err != nil {
		return false
	}
	return canAccess
}

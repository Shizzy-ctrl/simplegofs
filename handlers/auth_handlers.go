package handlers

import (
	"simplegofs/middleware"
	"simplegofs/repositories"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandlers struct {
	userRepo *repositories.UserRepository
}

func NewAuthHandlers(userRepo *repositories.UserRepository) *AuthHandlers {
	return &AuthHandlers{userRepo: userRepo}
}

// LoginHandler handles GET and POST for login
func (h *AuthHandlers) LoginHandler(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		return c.Render("login", fiber.Map{})
	}

	// POST request
	username := c.FormValue("username")
	password := c.FormValue("password")

	user, err := h.userRepo.GetByUsername(username)
	if err != nil {
		return c.Render("login", fiber.Map{
			"Error": "Invalid username or password",
		})
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return c.Render("login", fiber.Map{
			"Error": "Invalid username or password",
		})
	}

	// Create session
	token := middleware.CreateSession(username, user.IsAdmin)
	c.Cookie(&fiber.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HTTPOnly: true,
		MaxAge:   86400, // 24 hours
	})

	return c.Redirect("/")
}

// LogoutHandler handles POST logout
func (h *AuthHandlers) LogoutHandler(c *fiber.Ctx) error {
	token := c.Cookies("session_token")
	if token != "" {
		middleware.DeleteSession(token)
	}

	c.ClearCookie("session_token")
	return c.Redirect("/login")
}

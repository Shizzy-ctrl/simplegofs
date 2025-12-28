package handlers

import (
	"os"

	"simplegofs/models"
	"simplegofs/repositories"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

type AdminHandlers struct {
	userRepo *repositories.UserRepository
	permRepo *repositories.PermissionRepository
}

func NewAdminHandlers(userRepo *repositories.UserRepository, permRepo *repositories.PermissionRepository) *AdminHandlers {
	return &AdminHandlers{
		userRepo: userRepo,
		permRepo: permRepo,
	}
}

// AdminFileInfo represents file info with permissions for admin panel
type AdminFileInfo struct {
	Name        string
	Size        string
	Permissions map[string]bool
}

// AdminHandler displays the admin dashboard
func (h *AdminHandlers) AdminHandler(c *fiber.Ctx) error {
	username := c.Locals("username").(string)

	files, err := os.ReadDir("files")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Unable to read directory")
	}

	var fileInfos []AdminFileInfo
	for _, f := range files {
		if !f.IsDir() {
			info, _ := f.Info()

			allowedUsers, _ := h.permRepo.GetFilePermissions(f.Name())
			perms := make(map[string]bool)
			for _, u := range allowedUsers {
				perms[u] = true
			}

			fileInfos = append(fileInfos, AdminFileInfo{
				Name:        f.Name(),
				Size:        formatSize(info.Size()),
				Permissions: perms,
			})
		}
	}

	// Get all non-admin users
	users, _ := h.userRepo.GetNonAdminUsers()
	var userList []string
	for _, user := range users {
		userList = append(userList, user.Username)
	}

	data := fiber.Map{
		"Username": username,
		"Files":    fileInfos,
		"Users":    userList,
		"Success":  c.Query("success"),
		"Error":    c.Query("error"),
	}

	return c.Render("admin", data)
}

// PermissionsHandler updates file permissions
func (h *AdminHandlers) PermissionsHandler(c *fiber.Ctx) error {
	filename := c.FormValue("filename")
	selectedUsers := c.Request().PostArgs().PeekMulti("users")

	var usernames []string
	for _, user := range selectedUsers {
		usernames = append(usernames, string(user))
	}

	if err := h.permRepo.SetFilePermissions(filename, usernames); err != nil {
		return c.Redirect("/admin?error=Failed to save permissions")
	}

	return c.Redirect("/admin?success=Permissions updated")
}

// UsersHandler displays user management page
func (h *AdminHandlers) UsersHandler(c *fiber.Ctx) error {
	username := c.Locals("username").(string)

	users, err := h.userRepo.GetAll()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Unable to load users")
	}

	data := fiber.Map{
		"Username": username,
		"Users":    users,
		"Success":  c.Query("success"),
		"Error":    c.Query("error"),
	}

	return c.Render("users", data)
}

// CreateUserHandler creates a new user
func (h *AdminHandlers) CreateUserHandler(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	isAdmin := c.FormValue("is_admin") == "true"

	if username == "" || password == "" {
		return c.Redirect("/admin/users?error=Username and password required")
	}

	if len(password) < 6 {
		return c.Redirect("/admin/users?error=Password must be at least 6 characters")
	}

	exists, _ := h.userRepo.Exists(username)
	if exists {
		return c.Redirect("/admin/users?error=User already exists")
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return c.Redirect("/admin/users?error=Failed to hash password")
	}

	user := &models.User{
		Username:     username,
		PasswordHash: string(hash),
		IsAdmin:      isAdmin,
	}

	if err := h.userRepo.Create(user); err != nil {
		return c.Redirect("/admin/users?error=Failed to create user")
	}

	return c.Redirect("/admin/users?success=User created successfully")
}

// DeleteUserHandler deletes a user
func (h *AdminHandlers) DeleteUserHandler(c *fiber.Ctx) error {
	username := c.FormValue("username")
	if username == "" {
		return c.Redirect("/admin/users?error=Username required")
	}

	user, err := h.userRepo.GetByUsername(username)
	if err != nil {
		return c.Redirect("/admin/users?error=User not found")
	}

	if user.IsAdmin {
		return c.Redirect("/admin/users?error=Cannot delete admin users")
	}

	// Remove user from all permissions
	if err := h.permRepo.RemoveUserFromAllPermissions(username); err != nil {
		return c.Redirect("/admin/users?error=Failed to update permissions")
	}

	if err := h.userRepo.Delete(username); err != nil {
		return c.Redirect("/admin/users?error=Failed to delete user")
	}

	return c.Redirect("/admin/users?success=User deleted successfully")
}

// ResetPasswordHandler resets a user's password
func (h *AdminHandlers) ResetPasswordHandler(c *fiber.Ctx) error {
	username := c.FormValue("username")
	newPassword := c.FormValue("new_password")

	if username == "" || newPassword == "" {
		return c.Redirect("/admin/users?error=Username and new password required")
	}

	if len(newPassword) < 6 {
		return c.Redirect("/admin/users?error=Password must be at least 6 characters")
	}

	user, err := h.userRepo.GetByUsername(username)
	if err != nil {
		return c.Redirect("/admin/users?error=User not found")
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Redirect("/admin/users?error=Failed to hash password")
	}

	user.PasswordHash = string(hash)

	if err := h.userRepo.Update(user); err != nil {
		return c.Redirect("/admin/users?error=Failed to save changes")
	}

	return c.Redirect("/admin/users?success=Password reset successfully")
}

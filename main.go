package main

import (
	"fmt"
	"log"
	"os"

	"simplegofs/database"
	"simplegofs/handlers"
	"simplegofs/middleware"
	"simplegofs/repositories"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
)

const (
	staticDir    = "static"
	filesDir     = "files"
	templatesDir = "templates"
)

func main() {
	// Create necessary directories
	os.MkdirAll(staticDir, 0755)
	os.MkdirAll(filesDir, 0755)
	os.MkdirAll(templatesDir, 0755)

	// Connect to database
	if err := database.Connect(); err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Run migrations
	if err := database.Migrate(); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Create initial admin user
	if err := database.CreateInitialAdmin(); err != nil {
		log.Fatal("Failed to create admin user:", err)
	}

	// Initialize repositories
	userRepo := repositories.NewUserRepository()
	permRepo := repositories.NewPermissionRepository()

	// Initialize handlers
	authHandlers := handlers.NewAuthHandlers(userRepo)
	fileHandlers := handlers.NewFileHandlers(permRepo)
	adminHandlers := handlers.NewAdminHandlers(userRepo, permRepo)

	// Initialize Fiber template engine
	engine := html.New(templatesDir, ".html")
	engine.Reload(true) // Enable auto-reload in development

	// Create Fiber app
	app := fiber.New(fiber.Config{
		Views:       engine,
		ViewsLayout: "",
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())

	// Static files
	app.Static("/static", staticDir)

	// Public routes
	app.All("/login", authHandlers.LoginHandler)
	app.Post("/logout", authHandlers.LogoutHandler)

	// Protected routes
	app.Use(middleware.RequireAuth())

	// File routes
	app.Get("/", fileHandlers.FileListHandler)
	app.Get("/files/*", fileHandlers.FileHandler)
	app.Get("/download/*", fileHandlers.DownloadHandler)

	// Admin routes
	admin := app.Group("/admin", middleware.RequireAdmin())
	admin.Get("/", adminHandlers.AdminHandler)
	admin.Post("/upload", fileHandlers.UploadHandler)
	admin.Post("/permissions", adminHandlers.PermissionsHandler)

	// User management routes
	admin.Get("/users", adminHandlers.UsersHandler)
	admin.Post("/create-user", adminHandlers.CreateUserHandler)
	admin.Post("/delete-user", adminHandlers.DeleteUserHandler)
	admin.Post("/reset-password", adminHandlers.ResetPasswordHandler)

	// Start server
	fmt.Println("File server available at http://localhost:8080/")
	log.Fatal(app.Listen(":8080"))
}

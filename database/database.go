package database

import (
	"fmt"
	"log"
	"os"

	"simplegofs/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Connect initializes the database connection
func Connect() error {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "fileserver")
	password := getEnv("DB_PASSWORD", "fileserver_pass")
	dbname := getEnv("DB_NAME", "fileserver")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		host, user, password, dbname, port)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	log.Println("Database connection established")
	return nil
}

// Migrate runs auto-migration for all models
func Migrate() error {
	log.Println("Running database migrations...")

	err := DB.AutoMigrate(
		&models.User{},
		&models.FileMetadata{},
		&models.Permission{},
	)
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	log.Println("Database migrations completed")
	return nil
}

// CreateInitialAdmin creates the initial admin user from environment variables
func CreateInitialAdmin() error {
	adminUsername := getEnv("ADMIN_USERNAME", "admin")
	adminPassword := getEnv("ADMIN_PASSWORD", "admin123")

	// Check if admin already exists
	var existingUser models.User
	result := DB.Where("username = ?", adminUsername).First(&existingUser)
	if result.Error == nil {
		log.Printf("Admin user '%s' already exists", adminUsername)
		return nil
	}

	// Create admin user
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	admin := models.User{
		Username:     adminUsername,
		PasswordHash: string(hash),
		IsAdmin:      true,
	}

	if err := DB.Create(&admin).Error; err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	log.Printf("Created admin user '%s'", adminUsername)
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

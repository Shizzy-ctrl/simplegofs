package repositories

import (
	"simplegofs/database"
	"simplegofs/models"
)

// UserRepository handles user data operations
type UserRepository struct{}

// NewUserRepository creates a new user repository
func NewUserRepository() *UserRepository {
	return &UserRepository{}
}

// Create creates a new user
func (r *UserRepository) Create(user *models.User) error {
	return database.DB.Create(user).Error
}

// GetByUsername retrieves a user by username
func (r *UserRepository) GetByUsername(username string) (*models.User, error) {
	var user models.User
	err := database.DB.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetAll retrieves all users
func (r *UserRepository) GetAll() ([]models.User, error) {
	var users []models.User
	err := database.DB.Find(&users).Error
	return users, err
}

// GetNonAdminUsers retrieves all non-admin users
func (r *UserRepository) GetNonAdminUsers() ([]models.User, error) {
	var users []models.User
	err := database.DB.Where("is_admin = ?", false).Find(&users).Error
	return users, err
}

// Update updates a user
func (r *UserRepository) Update(user *models.User) error {
	return database.DB.Save(user).Error
}

// Delete deletes a user by username
func (r *UserRepository) Delete(username string) error {
	return database.DB.Where("username = ?", username).Delete(&models.User{}).Error
}

// Exists checks if a user exists
func (r *UserRepository) Exists(username string) (bool, error) {
	var count int64
	err := database.DB.Model(&models.User{}).Where("username = ?", username).Count(&count).Error
	return count > 0, err
}

package repositories

import (
	"simplegofs/database"
	"simplegofs/models"
)

// PermissionRepository handles permission data operations
type PermissionRepository struct{}

// NewPermissionRepository creates a new permission repository
func NewPermissionRepository() *PermissionRepository {
	return &PermissionRepository{}
}

// SetFilePermissions sets permissions for a file (replaces existing)
func (r *PermissionRepository) SetFilePermissions(filename string, usernames []string) error {
	// Start transaction
	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Delete existing permissions for this file
	if err := tx.Where("filename = ?", filename).Delete(&models.Permission{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Create new permissions
	for _, username := range usernames {
		var user models.User
		if err := tx.Where("username = ?", username).First(&user).Error; err != nil {
			tx.Rollback()
			return err
		}

		permission := models.Permission{
			UserID:   user.ID,
			Filename: filename,
		}
		if err := tx.Create(&permission).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

// GetFilePermissions retrieves usernames that have access to a file
func (r *PermissionRepository) GetFilePermissions(filename string) ([]string, error) {
	var permissions []models.Permission
	err := database.DB.Preload("User").Where("filename = ?", filename).Find(&permissions).Error
	if err != nil {
		return nil, err
	}

	usernames := make([]string, len(permissions))
	for i, p := range permissions {
		usernames[i] = p.User.Username
	}
	return usernames, nil
}

// GetAllPermissions retrieves all permissions as a map[filename][]username
func (r *PermissionRepository) GetAllPermissions() (map[string][]string, error) {
	var permissions []models.Permission
	err := database.DB.Preload("User").Find(&permissions).Error
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string)
	for _, p := range permissions {
		result[p.Filename] = append(result[p.Filename], p.User.Username)
	}
	return result, nil
}

// CanUserAccessFile checks if a user can access a file
func (r *PermissionRepository) CanUserAccessFile(username, filename string) (bool, error) {
	var count int64
	err := database.DB.Model(&models.Permission{}).
		Joins("JOIN users ON users.id = permissions.user_id").
		Where("users.username = ? AND permissions.filename = ?", username, filename).
		Count(&count).Error

	return count > 0, err
}

// RemoveUserFromAllPermissions removes a user from all file permissions
func (r *PermissionRepository) RemoveUserFromAllPermissions(username string) error {
	return database.DB.
		Where("user_id IN (SELECT id FROM users WHERE username = ?)", username).
		Delete(&models.Permission{}).Error
}

// GetUserPermissions retrieves all files a user has access to
func (r *PermissionRepository) GetUserPermissions(username string) ([]string, error) {
	var permissions []models.Permission
	err := database.DB.
		Joins("JOIN users ON users.id = permissions.user_id").
		Where("users.username = ?", username).
		Find(&permissions).Error

	if err != nil {
		return nil, err
	}

	filenames := make([]string, len(permissions))
	for i, p := range permissions {
		filenames[i] = p.Filename
	}
	return filenames, nil
}

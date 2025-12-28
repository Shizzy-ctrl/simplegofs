package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID           uint `gorm:"primarykey"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
	Username     string         `gorm:"uniqueIndex;not null"`
	PasswordHash string         `gorm:"not null"`
	IsAdmin      bool           `gorm:"default:false"`
}

// FileMetadata represents metadata about uploaded files
type FileMetadata struct {
	ID         uint `gorm:"primarykey"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  gorm.DeletedAt `gorm:"index"`
	Filename   string         `gorm:"uniqueIndex;not null"`
	Size       int64
	UploadedBy string
}

// Permission represents user access to files
type Permission struct {
	ID        uint   `gorm:"primarykey"`
	UserID    uint   `gorm:"not null;index:idx_user_file"`
	Filename  string `gorm:"not null;index:idx_user_file"`
	User      User   `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	CreatedAt time.Time
}

package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"simplegofs/middleware"
	"simplegofs/repositories"

	"github.com/gofiber/fiber/v2"
)

const filesDir = "files"

type FileHandlers struct {
	permRepo *repositories.PermissionRepository
}

func NewFileHandlers(permRepo *repositories.PermissionRepository) *FileHandlers {
	return &FileHandlers{permRepo: permRepo}
}

// FileInfo represents file information for templates
type FileInfo struct {
	Name          string
	Size          string
	IsPreviewable bool
}

// PageData represents data for the file list page
type PageData struct {
	Files    []FileInfo
	Username string
	IsAdmin  bool
}

// FileListHandler displays list of accessible files
func (h *FileHandlers) FileListHandler(c *fiber.Ctx) error {
	username := c.Locals("username").(string)
	isAdmin := c.Locals("isAdmin").(bool)

	files, err := os.ReadDir(filesDir)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Unable to read directory")
	}

	var fileInfos []FileInfo
	for _, f := range files {
		if !f.IsDir() {
			if middleware.CanAccessFile(username, f.Name(), isAdmin, h.permRepo) {
				info, _ := f.Info()
				ext := filepath.Ext(f.Name())
				fileInfos = append(fileInfos, FileInfo{
					Name:          f.Name(),
					Size:          formatSize(info.Size()),
					IsPreviewable: isPreviewable(strings.TrimPrefix(ext, ".")),
				})
			}
		}
	}

	data := PageData{
		Files:    fileInfos,
		Username: username,
		IsAdmin:  isAdmin,
	}

	return c.Render("index", data)
}

// FileHandler serves or previews a file
func (h *FileHandlers) FileHandler(c *fiber.Ctx) error {
	// Redundant auth check
	token := c.Cookies("session_token")
	if token == "" {
		return c.Redirect("/login")
	}
	if _, valid := middleware.GetSession(token); !valid {
		return c.Redirect("/login")
	}

	username := c.Locals("username").(string)
	isAdmin := c.Locals("isAdmin").(bool)

	filename := c.Params("*")
	if filename == "" {
		return c.Redirect("/")
	}

	if !middleware.CanAccessFile(username, filename, isAdmin, h.permRepo) {
		return c.Status(fiber.StatusForbidden).SendString("Access denied")
	}

	filepath := filepath.Join(filesDir, filename)

	info, err := os.Stat(filepath)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}

	if info.IsDir() {
		return c.Status(fiber.StatusBadRequest).SendString("Is a directory")
	}

	ext := strings.ToLower(filepath[strings.LastIndex(filepath, ".")+1:])
	contentType := getContentType(ext)

	c.Set("Content-Type", contentType)
	// Disable caching for sensitive files
	c.Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
	c.Set("Pragma", "no-cache")
	c.Set("Expires", "0")

	if !isPreviewable(ext) {
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	}

	return c.SendFile(filepath)
}

// DownloadHandler forces file download
func (h *FileHandlers) DownloadHandler(c *fiber.Ctx) error {
	// Redundant auth check
	token := c.Cookies("session_token")
	if token == "" {
		return c.Redirect("/login")
	}
	if _, valid := middleware.GetSession(token); !valid {
		return c.Redirect("/login")
	}

	username := c.Locals("username").(string)
	isAdmin := c.Locals("isAdmin").(bool)

	filename := c.Params("*")
	if filename == "" {
		return c.Redirect("/")
	}

	if !middleware.CanAccessFile(username, filename, isAdmin, h.permRepo) {
		return c.Status(fiber.StatusForbidden).SendString("Access denied")
	}

	filepath := filepath.Join(filesDir, filename)

	if _, err := os.Stat(filepath); err != nil {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}

	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Set("Content-Type", "application/octet-stream")
	// Disable caching
	c.Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
	c.Set("Pragma", "no-cache")
	c.Set("Expires", "0")

	return c.SendFile(filepath)
}

// UploadHandler handles file uploads (admin only)
func (h *FileHandlers) UploadHandler(c *fiber.Ctx) error {
	file, err := c.FormFile("file")
	if err != nil {
		return c.Redirect("/admin?error=" + err.Error())
	}

	dst := filepath.Join(filesDir, file.Filename)
	if err := c.SaveFile(file, dst); err != nil {
		return c.Redirect("/admin?error=" + err.Error())
	}

	return c.Redirect("/admin?success=File uploaded successfully")
}

// Helper functions

func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func getContentType(ext string) string {
	types := map[string]string{
		"txt":  "text/plain; charset=utf-8",
		"html": "text/html; charset=utf-8",
		"css":  "text/css",
		"js":   "application/javascript",
		"json": "application/json",
		"xml":  "application/xml",
		"pdf":  "application/pdf",
		"jpg":  "image/jpeg",
		"jpeg": "image/jpeg",
		"png":  "image/png",
		"gif":  "image/gif",
		"svg":  "image/svg+xml",
		"mp3":  "audio/mpeg",
		"mp4":  "video/mp4",
		"zip":  "application/zip",
		"tar":  "application/x-tar",
		"gz":   "application/gzip",
	}

	if ct, ok := types[ext]; ok {
		return ct
	}
	return "application/octet-stream"
}

func isPreviewable(ext string) bool {
	previewable := map[string]bool{
		"txt": true, "html": true, "css": true, "js": true,
		"json": true, "xml": true, "pdf": true,
		"jpg": true, "jpeg": true, "png": true, "gif": true, "svg": true,
		"mp3": true, "mp4": true,
	}
	return previewable[ext]
}

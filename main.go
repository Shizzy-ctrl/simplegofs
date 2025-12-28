package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	staticDir         = "static"
	filesDir          = "files"
	templatesDir      = "templates"
	permissionsFile   = "permissions.json"
	usersFile         = "users.json"
	sessionCookieName = "session_token"
)

// User represents a user with role
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	IsAdmin      bool   `json:"is_admin"`
}

// Session represents an active user session
type Session struct {
	Username  string
	IsAdmin   bool
	ExpiresAt time.Time
}

// Permissions maps filename -> list of usernames who can access
type Permissions map[string][]string

var (
	users       map[string]*User
	sessions    map[string]*Session
	permissions Permissions
	sessionMu   sync.RWMutex
	permMu      sync.RWMutex
	templates   *template.Template
)

func main() {
	os.MkdirAll(staticDir, 0755)
	os.MkdirAll(filesDir, 0755)
	os.MkdirAll(templatesDir, 0755)

	loadUsers()
	loadPermissions()
	loadTemplates()

	sessions = make(map[string]*Session)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/admin", requireAuth(requireAdmin(adminHandler)))
	http.HandleFunc("/admin/users", requireAuth(requireAdmin(usersHandler)))
	http.HandleFunc("/admin/create-user", requireAuth(requireAdmin(createUserHandler)))
	http.HandleFunc("/admin/delete-user", requireAuth(requireAdmin(deleteUserHandler)))
	http.HandleFunc("/admin/reset-password", requireAuth(requireAdmin(resetPasswordHandler)))
	http.HandleFunc("/upload", requireAuth(requireAdmin(uploadHandler)))
	http.HandleFunc("/permissions", requireAuth(requireAdmin(permissionsHandler)))
	http.HandleFunc("/files/", requireAuth(fileHandler))
	http.HandleFunc("/download/", requireAuth(downloadHandler))
	http.HandleFunc("/", requireAuth(fileListHandler))

	fmt.Println("File server available at http://localhost:8080/")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loadUsers() {
	users = make(map[string]*User)

	// Try to load from users.json first
	data, err := os.ReadFile(usersFile)
	if err == nil {
		var userList []User
		if err := json.Unmarshal(data, &userList); err == nil {
			for _, u := range userList {
				users[u.Username] = &User{
					Username:     u.Username,
					PasswordHash: u.PasswordHash,
					IsAdmin:      u.IsAdmin,
				}
			}
			log.Printf("Loaded %d users from %s", len(users), usersFile)
			return
		}
	}

	// Fallback: load admin from .env and migrate to users.json
	log.Println("users.json not found, loading admin from .env")
	envData, err := os.ReadFile(".env")
	if err != nil {
		log.Println(".env file not found - creating example")
		createExampleEnv()
		envData, _ = os.ReadFile(".env")
	}

	var adminUsername, adminPassword string
	lines := strings.Split(string(envData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "ADMIN_USERNAME" {
			adminUsername = value
		} else if key == "ADMIN_PASSWORD" {
			adminPassword = value
		}
	}

	if adminUsername == "" || adminPassword == "" {
		log.Fatal("ADMIN_USERNAME and ADMIN_PASSWORD required in .env")
	}

	// Create admin user with hashed password
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash admin password:", err)
	}

	users[adminUsername] = &User{
		Username:     adminUsername,
		PasswordHash: string(hash),
		IsAdmin:      true,
	}

	// Save to users.json
	if err := saveUsers(); err != nil {
		log.Fatal("Failed to save users:", err)
	}

	log.Printf("Created admin user '%s' from .env", adminUsername)
}

func createExampleEnv() {
	content := `# FileServer - Configuration
# Initial admin user (other users can be created from admin panel)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
`
	os.WriteFile(".env", []byte(content), 0644)
}

func saveUsers() error {
	var userList []User
	for _, u := range users {
		userList = append(userList, *u)
	}

	data, err := json.MarshalIndent(userList, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(usersFile, data, 0644)
}

func loadPermissions() {
	permMu.Lock()
	defer permMu.Unlock()

	permissions = make(Permissions)

	data, err := os.ReadFile(permissionsFile)
	if err != nil {
		// File doesn't exist yet, start with empty permissions
		return
	}

	if err := json.Unmarshal(data, &permissions); err != nil {
		log.Printf("Error loading permissions: %v", err)
	}
}

func savePermissions() error {
	permMu.RLock()
	defer permMu.RUnlock()

	data, err := json.MarshalIndent(permissions, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(permissionsFile, data, 0644)
}

func loadTemplates() {
	var err error
	templates, err = template.ParseGlob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		log.Fatal("Error loading templates:", err)
	}
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func createSession(username string, isAdmin bool) string {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	token := generateSessionToken()
	sessions[token] = &Session{
		Username:  username,
		IsAdmin:   isAdmin,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	return token
}

func getSession(token string) (*Session, bool) {
	sessionMu.RLock()
	defer sessionMu.RUnlock()

	session, exists := sessions[token]
	if !exists || time.Now().After(session.ExpiresAt) {
		return nil, false
	}
	return session, true
}

func deleteSession(token string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	delete(sessions, token)
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		session, valid := getSession(cookie.Value)
		if !valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Store session in context (simple approach: use custom header)
		r.Header.Set("X-Username", session.Username)
		r.Header.Set("X-IsAdmin", fmt.Sprintf("%t", session.IsAdmin))

		next(w, r)
	}
}

func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		isAdmin := r.Header.Get("X-IsAdmin") == "true"
		if !isAdmin {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, exists := users[username]
		if !exists {
			templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
				"Error": "Invalid username or password",
			})
			return
		}

		// Verify password with bcrypt
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
				"Error": "Invalid username or password",
			})
			return
		}

		token := createSession(username, user.IsAdmin)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400, // 24 hours
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		deleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func canAccess(username string, filename string, isAdmin bool) bool {
	if isAdmin {
		return true
	}

	permMu.RLock()
	defer permMu.RUnlock()

	allowedUsers, exists := permissions[filename]
	if !exists {
		return false
	}

	for _, u := range allowedUsers {
		if u == username {
			return true
		}
	}
	return false
}

func fileListHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	username := r.Header.Get("X-Username")
	isAdmin := r.Header.Get("X-IsAdmin") == "true"

	files, err := os.ReadDir(filesDir)
	if err != nil {
		http.Error(w, "Unable to read directory", http.StatusInternalServerError)
		return
	}

	var fileInfos []FileInfo
	for _, f := range files {
		if !f.IsDir() {
			if canAccess(username, f.Name(), isAdmin) {
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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "index.html", data)
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")
	isAdmin := r.Header.Get("X-IsAdmin") == "true"

	filename := strings.TrimPrefix(r.URL.Path, "/files/")
	if filename == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !canAccess(username, filename, isAdmin) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	filepath := filepath.Join(filesDir, filename)

	info, err := os.Stat(filepath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if info.IsDir() {
		http.Error(w, "Is a directory", http.StatusBadRequest)
		return
	}

	ext := strings.ToLower(filepath[strings.LastIndex(filepath, ".")+1:])
	contentType := getContentType(ext)

	w.Header().Set("Content-Type", contentType)

	if !isPreviewable(ext) {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	}

	http.ServeFile(w, r, filepath)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")
	isAdmin := r.Header.Get("X-IsAdmin") == "true"

	filename := strings.TrimPrefix(r.URL.Path, "/download/")
	if filename == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !canAccess(username, filename, isAdmin) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	filepath := filepath.Join(filesDir, filename)

	if _, err := os.Stat(filepath); err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/octet-stream")

	http.ServeFile(w, r, filepath)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")

	files, err := os.ReadDir(filesDir)
	if err != nil {
		http.Error(w, "Unable to read directory", http.StatusInternalServerError)
		return
	}

	type AdminFileInfo struct {
		Name        string
		Size        string
		Permissions map[string]bool
	}

	var fileInfos []AdminFileInfo
	for _, f := range files {
		if !f.IsDir() {
			info, _ := f.Info()

			permMu.RLock()
			allowedUsers := permissions[f.Name()]
			permMu.RUnlock()

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
	var userList []string
	for _, user := range users {
		if !user.IsAdmin {
			userList = append(userList, user.Username)
		}
	}

	data := map[string]interface{}{
		"Username": username,
		"Files":    fileInfos,
		"Users":    userList,
		"Success":  r.URL.Query().Get("success"),
		"Error":    r.URL.Query().Get("error"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "admin.html", data)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Redirect(w, r, "/admin?error="+err.Error(), http.StatusSeeOther)
		return
	}
	defer file.Close()

	dst, err := os.Create(filepath.Join(filesDir, header.Filename))
	if err != nil {
		http.Redirect(w, r, "/admin?error="+err.Error(), http.StatusSeeOther)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Redirect(w, r, "/admin?error="+err.Error(), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin?success=File uploaded successfully", http.StatusSeeOther)
}

func permissionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.FormValue("filename")
	selectedUsers := r.Form["users"]

	permMu.Lock()
	permissions[filename] = selectedUsers
	permMu.Unlock()

	if err := savePermissions(); err != nil {
		http.Redirect(w, r, "/admin?error=Failed to save permissions", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin?success=Permissions updated", http.StatusSeeOther)
}

type FileInfo struct {
	Name          string
	Size          string
	IsPreviewable bool
}

type PageData struct {
	Files    []FileInfo
	Username string
	IsAdmin  bool
}

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

func usersHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")

	var userList []User
	for _, user := range users {
		userList = append(userList, *user)
	}

	data := map[string]interface{}{
		"Username": username,
		"Users":    userList,
		"Success":  r.URL.Query().Get("success"),
		"Error":    r.URL.Query().Get("error"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "users.html", data)
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	isAdmin := r.FormValue("is_admin") == "true"

	if username == "" || password == "" {
		http.Redirect(w, r, "/admin/users?error=Username and password required", http.StatusSeeOther)
		return
	}

	if len(password) < 6 {
		http.Redirect(w, r, "/admin/users?error=Password must be at least 6 characters", http.StatusSeeOther)
		return
	}

	if _, exists := users[username]; exists {
		http.Redirect(w, r, "/admin/users?error=User already exists", http.StatusSeeOther)
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Redirect(w, r, "/admin/users?error=Failed to hash password", http.StatusSeeOther)
		return
	}

	users[username] = &User{
		Username:     username,
		PasswordHash: string(hash),
		IsAdmin:      isAdmin,
	}

	if err := saveUsers(); err != nil {
		http.Redirect(w, r, "/admin/users?error=Failed to save user", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/users?success=User created successfully", http.StatusSeeOther)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	if username == "" {
		http.Redirect(w, r, "/admin/users?error=Username required", http.StatusSeeOther)
		return
	}

	user, exists := users[username]
	if !exists {
		http.Redirect(w, r, "/admin/users?error=User not found", http.StatusSeeOther)
		return
	}

	if user.IsAdmin {
		http.Redirect(w, r, "/admin/users?error=Cannot delete admin users", http.StatusSeeOther)
		return
	}

	delete(users, username)

	// Remove user from all file permissions
	permMu.Lock()
	for filename, allowedUsers := range permissions {
		var newUsers []string
		for _, u := range allowedUsers {
			if u != username {
				newUsers = append(newUsers, u)
			}
		}
		permissions[filename] = newUsers
	}
	permMu.Unlock()

	if err := saveUsers(); err != nil {
		http.Redirect(w, r, "/admin/users?error=Failed to save changes", http.StatusSeeOther)
		return
	}

	if err := savePermissions(); err != nil {
		http.Redirect(w, r, "/admin/users?error=User deleted but failed to update permissions", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/users?success=User deleted successfully", http.StatusSeeOther)
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	newPassword := r.FormValue("new_password")

	if username == "" || newPassword == "" {
		http.Redirect(w, r, "/admin/users?error=Username and new password required", http.StatusSeeOther)
		return
	}

	if len(newPassword) < 6 {
		http.Redirect(w, r, "/admin/users?error=Password must be at least 6 characters", http.StatusSeeOther)
		return
	}

	user, exists := users[username]
	if !exists {
		http.Redirect(w, r, "/admin/users?error=User not found", http.StatusSeeOther)
		return
	}

	// Hash the new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Redirect(w, r, "/admin/users?error=Failed to hash password", http.StatusSeeOther)
		return
	}

	user.PasswordHash = string(hash)

	if err := saveUsers(); err != nil {
		http.Redirect(w, r, "/admin/users?error=Failed to save changes", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/users?success=Password reset successfully", http.StatusSeeOther)
}


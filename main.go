package main

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	staticDir = "static"
	filesDir  = "files"
)

var allowedUsers map[string]string

func main() {
	os.MkdirAll(staticDir, 0755)
	os.MkdirAll(filesDir, 0755)

	loadUsers()

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
	http.HandleFunc("/files/", basicAuth(fileHandler))
	http.HandleFunc("/download/", basicAuth(downloadHandler))
	http.HandleFunc("/", basicAuth(fileListHandler))

	fmt.Println("File server available at http://localhost:8080/")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loadUsers() {
	allowedUsers = make(map[string]string)

	file, err := os.Open(".env")
	if err != nil {
		log.Println(".env file not found - creating example")
		createExampleEnv()
		file, _ = os.Open(".env")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if strings.HasPrefix(key, "USER_") {
			username := strings.TrimPrefix(key, "USER_")
			allowedUsers[username] = value
		}
	}

	if len(allowedUsers) == 0 {
		log.Fatal("No users in .env!")
	}

	log.Printf("Loaded %d users", len(allowedUsers))
}

func createExampleEnv() {
	content := `# FileServer - User Configuration
# Format: USER_name=password

USER_admin=admin123
USER_guest=password1
`
	os.WriteFile(".env", []byte(content), 0644)
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()

		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="FileServer"`)
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		expectedPassword, userExists := allowedUsers[username]

		if !userExists || subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="FileServer"`)
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/files/")
	if filename == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
	filename := strings.TrimPrefix(r.URL.Path, "/download/")
	if filename == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
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

func fileListHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	files, err := os.ReadDir(filesDir)
	if err != nil {
		http.Error(w, "Unable to read directory", http.StatusInternalServerError)
		return
	}

	var fileInfos []FileInfo
	for _, f := range files {
		if !f.IsDir() {
			info, _ := f.Info()
			ext := filepath.Ext(f.Name())
			fileInfos = append(fileInfos, FileInfo{
				Name:          f.Name(),
				Size:          formatSize(info.Size()),
				IsPreviewable: isPreviewable(strings.TrimPrefix(ext, ".")),
			})
		}
	}

	username, _, _ := r.BasicAuth()
	data := PageData{
		Files:    fileInfos,
		Username: username,
	}

	tmpl := template.Must(template.New("index").Parse(htmlIndex))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

type FileInfo struct {
	Name          string
	Size          string
	IsPreviewable bool
}

type PageData struct {
	Files    []FileInfo
	Username string
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

const htmlIndex = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>FileServer</title>
	<link rel="stylesheet" href="/static/style.css">
	<meta http-equiv="refresh" content="5">
</head>
<body>
	<div class="container">
		<header>
			<h1>File Server</h1>
			<div class="user-info">Logged in as: <strong>{{.Username}}</strong></div>
		</header>
		
		<main class="file-list">
			{{if .Files}}
			<table>
				<thead>
					<tr>
						<th>Filename</th>
						<th>Size</th>
						<th class="actions-col">Actions</th>
					</tr>
				</thead>
				<tbody>
				{{range .Files}}
					<tr>
						<td class="filename">
							{{if .IsPreviewable}}
								<a href="/files/{{.Name}}" target="_blank">{{.Name}}</a>
							{{else}}
								{{.Name}}
							{{end}}
						</td>
						<td class="filesize">{{.Size}}</td>
						<td class="actions">
							{{if .IsPreviewable}}
								<a href="/files/{{.Name}}" target="_blank" class="btn btn-preview">Preview</a>
							{{end}}
							<a href="/download/{{.Name}}" class="btn btn-download">Download</a>
						</td>
					</tr>
				{{end}}
				</tbody>
			</table>
			{{else}}
			<div class="empty-state">
				<p>No files to display</p>
				<p class="hint">Place files in the <code>files/</code> directory</p>
			</div>
			{{end}}
		</main>
	</div>
</body>
</html>
`

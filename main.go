package main

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/xid"
)

//go:embed all:static
var staticFiles embed.FS

var (
	db *sql.DB

	bindAddr      = flag.String("bind", "0.0.0.0", "Interface to bind to")
	port          = flag.Int("p", 8080, "Port to listen on")
	dataDir       = flag.String("d", "data", "Directory with db and files")
	maxUploadSize = flag.Int64("max-upload-size", 100*1024*1024, "Max file upload size")
	maxStorage    = flag.Int64("max-storage", 20*1024*1024*1024, "Max total storage limit")
	adminPassword = flag.String("admin-password", "", "Admin panel password (auto-generated if not set)")
	maxTTL        = flag.Duration("max-ttl", 168*time.Hour, "Max TTL duration (0 for permanent)")
)

type File struct {
	ID         string    `json:"id"`
	Filename   string    `json:"filename"`
	Size       int64     `json:"size"`
	Public     bool      `json:"public"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	UploadIP   string    `json:"upload_ip,omitempty"`
	URL        string    `json:"url"`
	DeleteURL  string    `json:"delete_url,omitempty"`
}

func main() {
	flag.Parse()

	if *adminPassword == "" {
		*adminPassword = generatePassword(24)
		log.Printf("Generated admin password: %s", *adminPassword)
	}

	if err := os.MkdirAll(filepath.Join(*dataDir, "files"), 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	var err error
	db, err = sql.Open("sqlite3", filepath.Join(*dataDir, "filedropper.db"))
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	createTable()

	go cleanupExpiredFiles()

	http.HandleFunc("/", handleIndex)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(getStaticFS())))
	http.HandleFunc("/upload/", handleUpload)
	http.HandleFunc("/public", handlePublicFiles)
	http.HandleFunc("/d/", handleDownload)
	http.HandleFunc("/admin", handleAdmin)
	http.HandleFunc("/admin/files", adminAuth(handleAdminFiles))
	http.HandleFunc("/admin/files/", adminAuth(handleAdminFile))

	addr := fmt.Sprintf("%s:%d", *bindAddr, *port)
	log.Printf("Server starting on http://%s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getStaticFS() http.FileSystem {
	ui, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}
	return http.FS(ui)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	f, err := getStaticFS().Open("index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, "index.html", time.Now(), f)
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	// Require basic auth
	user, pass, ok := r.BasicAuth()
	if !ok || user != "admin" || pass != *adminPassword {
		w.Header().Set("WWW-Authenticate", `Basic realm="Admin Panel"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	f, err := getStaticFS().Open("admin.html")
	if err != nil {
		http.Error(w, "admin.html not found", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, "admin.html", time.Now(), f)
}

func handlePutUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPut {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    filename := filepath.Base(r.URL.Path)
    if filename == "." || filename == "/" {
        http.Error(w, "Invalid filename", http.StatusBadRequest)
        return
    }

    handleFileUpload(w, r, r.Body, filename)
}


func handleUpload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		file, handler, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			if wantsJSON(r) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read file from form"})
			} else {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "error: Failed to read file from form\n")
			}
			return
		}
		defer file.Close()
		handleFileUpload(w, r, file, handler.Filename)
	case http.MethodPut:
		filename := strings.TrimPrefix(r.URL.Path, "/upload/")
		if filename == "" || filename == r.URL.Path {
			w.WriteHeader(http.StatusBadRequest)
			if wantsJSON(r) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"error": "Filename required in URL for PUT request"})
			} else {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "error: Filename required in URL for PUT request\n")
			}
			return
		}
		handleFileUpload(w, r, r.Body, filename)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		if wantsJSON(r) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		} else {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "error: Method not allowed\n")
		}
	}
}

func handleFileUpload(w http.ResponseWriter, r *http.Request, fileReader io.Reader, filename string) {
	// Get IP address
	ipAddress := getClientIP(r)

	// Parse TTL
	ttlStr := r.URL.Query().Get("expiration")
	var ttl time.Duration
	if ttlStr == "" {
		ttl = 7 * 24 * time.Hour // default 7d
	} else {
		var err error
		ttl, err = time.ParseDuration(ttlStr)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			if wantsJSON(r) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid expiration duration"})
			} else {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "error: Invalid expiration duration\n")
			}
			return
		}
	}

	// Handle permanent files
	if ttl == 0 {
		if *maxTTL != 0 {
			w.WriteHeader(http.StatusBadRequest)
			if wantsJSON(r) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"error": "Permanent files not allowed"})
			} else {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "error: Permanent files not allowed\n")
			}
			return
		}
		ttl = 100 * 365 * 24 * time.Hour
	}

	// Apply maximum TTL constraint
	if *maxTTL > 0 && ttl > *maxTTL {
		ttl = *maxTTL
	}

	// Apply minimum TTL constraint
	if ttl > 0 && ttl < 1*time.Minute {
		ttl = 1 * time.Minute
	}

	// Public
	publicStr := r.URL.Query().Get("public")
	public := publicStr == "yes"

	// Sanitize filename
	filename = sanitizeFilename(filename)

	id := xid.New().String()
	filePath := filepath.Join(*dataDir, "files", id)

	f, err := os.Create(filePath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		if wantsJSON(r) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create file"})
		} else {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "error: Failed to create file\n")
		}
		return
	}
	defer f.Close()

	size, err := io.Copy(f, io.LimitReader(fileReader, *maxUploadSize))
	if err != nil {
		os.Remove(filePath)
		w.WriteHeader(http.StatusInternalServerError)
		if wantsJSON(r) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to write file"})
		} else {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "error: Failed to write file\n")
		}
		return
	}

	// Check storage limit
	var totalSize int64
	err = db.QueryRow("SELECT COALESCE(SUM(size), 0) FROM files").Scan(&totalSize)
	if err == nil && totalSize+size > *maxStorage {
		os.Remove(filePath)
		w.WriteHeader(http.StatusInsufficientStorage)
		if wantsJSON(r) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "Storage limit exceeded"})
		} else {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "error: Storage limit exceeded\n")
		}
		return
	}

	fileEntry := &File{
		ID:        id,
		Filename:  filename,
		Size:      size,
		Public:    public,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
		UploadIP:  ipAddress,
	}

	if err := saveFileMeta(fileEntry); err != nil {
		os.Remove(filePath)
		w.WriteHeader(http.StatusInternalServerError)
		if wantsJSON(r) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save file metadata"})
		} else {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "error: Failed to save file metadata\n")
		}
		return
	}

	// Determine protocol from X-Forwarded-Proto header or default to https
	scheme := "https"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}

	url := fmt.Sprintf("%s://%s/d/%s/%s", scheme, r.Host, id, filename)

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"url":     url,
			"expires": fileEntry.ExpiresAt.Format(time.RFC3339),
			"public":  fmt.Sprintf("%t", public),
		})
	} else {
		w.Header().Set("Content-Type", "text/plain")
		duration := time.Until(fileEntry.ExpiresAt)
		fmt.Fprintf(w, "Here's your url: %s\nIt will expire on %s (%s)\n", url, fileEntry.ExpiresAt.Format("2006-01-02 15:04:05"), formatDuration(duration))
	}
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	
	if hours == 0 && minutes == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
}

func handlePublicFiles(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, filename, size, public, created_at, expires_at, upload_ip FROM files WHERE public = 1 AND expires_at > ?", time.Now().Format(time.RFC3339))
	if err != nil {
		http.Error(w, "Failed to query database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	files := []*File{}
	for rows.Next() {
		f := &File{}
		var createdAt, expiresAt string
		if err := rows.Scan(&f.ID, &f.Filename, &f.Size, &f.Public, &createdAt, &expiresAt, &f.UploadIP); err != nil {
			log.Printf("Error scanning file row: %v", err)
			continue
		}
		f.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		f.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
		f.URL = fmt.Sprintf("/d/%s/%s", f.ID, f.Filename)
		files = append(files, f)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/d/"), "/")
	if len(parts) < 1 {
		http.NotFound(w, r)
		return
	}
	id := parts[0]

	file, err := getFileMeta(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if len(parts) > 1 && parts[1] != file.Filename {
		http.NotFound(w, r)
		return
	}

	filePath := filepath.Join(*dataDir, "files", file.ID)
	
	// Force download with correct filename
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", file.Filename))
	
	http.ServeFile(w, r, filePath)
}

func handleAdminFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, filename, size, public, created_at, expires_at, upload_ip FROM files ORDER BY created_at DESC")
		if err != nil {
			http.Error(w, "Failed to query database", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		files := []*File{}
		for rows.Next() {
			f := &File{}
			var createdAt, expiresAt string
			if err := rows.Scan(&f.ID, &f.Filename, &f.Size, &f.Public, &createdAt, &expiresAt, &f.UploadIP); err != nil {
				log.Printf("Error scanning file row: %v", err)
				continue
			}
			f.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
			f.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
			f.URL = fmt.Sprintf("/d/%s/%s", f.ID, f.Filename)
			f.DeleteURL = fmt.Sprintf("/admin/files/%s", f.ID)
			files = append(files, f)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(files)
	} else if r.Method == http.MethodDelete {
		_, err := db.Exec("DELETE FROM files")
		if err != nil {
			http.Error(w, "Failed to delete all files from DB", http.StatusInternalServerError)
			return
		}
		filesDir := filepath.Join(*dataDir, "files")
		os.RemoveAll(filesDir)
		os.MkdirAll(filesDir, 0755)
		w.WriteHeader(http.StatusNoContent)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAdminFile(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    id := strings.TrimPrefix(r.URL.Path, "/admin/files/")
    
    // Validate ID: must exist in database (also prevents path traversal)
    _, err := getFileMeta(id)
    if err != nil {
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }

    if err := deleteFile(id); err != nil {
        http.Error(w, "Failed to delete file", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Try basic auth first
		user, pass, ok := r.BasicAuth()
		if ok && user == "admin" && pass == *adminPassword {
			next(w, r)
			return
		}

		// Try bearer token
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == *adminPassword {
				next(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="Admin Panel"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func createTable() {
	query := `
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  filename TEXT NOT NULL,
  size INTEGER NOT NULL,
  public INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  upload_ip TEXT DEFAULT ''
);`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

func saveFileMeta(file *File) error {
	_, err := db.Exec("INSERT INTO files (id, filename, size, public, created_at, expires_at, upload_ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
		file.ID, file.Filename, file.Size, file.Public, file.CreatedAt.Format(time.RFC3339), file.ExpiresAt.Format(time.RFC3339), file.UploadIP)
	return err
}

func getFileMeta(id string) (*File, error) {
	file := &File{}
	var createdAt, expiresAt string
	err := db.QueryRow("SELECT id, filename, size, public, created_at, expires_at, upload_ip FROM files WHERE id = ? AND expires_at > ?", id, time.Now().Format(time.RFC3339)).Scan(
		&file.ID, &file.Filename, &file.Size, &file.Public, &createdAt, &expiresAt, &file.UploadIP)
	if err != nil {
		return nil, err
	}
	file.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	file.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	return file, nil
}

func deleteFile(id string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM files WHERE id = ?", id)
	if err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return os.Remove(filepath.Join(*dataDir, "files", id))
}

func cleanupExpiredFiles() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rows, err := db.Query("SELECT id FROM files WHERE expires_at <= ?", time.Now().Format(time.RFC3339))
		if err != nil {
			log.Printf("Cleanup error: %v", err)
			continue
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				log.Printf("Cleanup scan error: %v", err)
				continue
			}
			ids = append(ids, id)
		}
		rows.Close()

		for _, id := range ids {
			log.Printf("Deleting expired file: %s", id)
			if err := deleteFile(id); err != nil {
				log.Printf("Failed to delete expired file %s: %v", id, err)
			}
		}
	}
}

func sanitizeFilename(filename string) string {
	filename = filepath.Base(filename)

	reg, _ := regexp.Compile(`[^a-zA-Z0-9._-]+`)
	sanitized := reg.ReplaceAllString(filename, "_")

	const maxLen = 200
	if len(sanitized) > maxLen {
		sanitized = sanitized[:maxLen]
	}

	return sanitized
}

func generatePassword(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Failed to generate random password: %v", err)
	}
	for i, v := range b {
		b[i] = chars[v%byte(len(chars))]
	}
	return string(b)
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fallback to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

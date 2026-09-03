package handler

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/log"
)

func (api *API) RegisterBackupApi() {
	api.mux.HandleFunc("/api/backup", api.handleBackup)
	api.mux.HandleFunc("/api/backup/restore", api.handleRestore)
}

// @Summary Download configuration backup
// @Tags Backup
// @Produce application/gzip
// @Success 200 {file} binary
// @Security BearerAuth
// @Router /backup [get]
// handleBackup creates a tar.gz of the config directory, excluding geodat and oui files.
func (api *API) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	configDir := filepath.Dir(api.getCfg().ConfigPath)
	if configDir == "" || configDir == "." {
		writeJsonError(w, http.StatusInternalServerError, "Config directory not configured")
		return
	}

	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("b4-backup-%s.tar.gz", timestamp)

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	gw := gzip.NewWriter(w)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	err := filepath.Walk(configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if shouldExcludeFromBackup(info) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, err := filepath.Rel(configDir, path)
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(tw, f)
		return err
	})

	if err != nil {
		log.Errorf("Backup creation failed: %v", err)
	}
}

// @Summary Restore configuration from backup
// @Tags Backup
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Backup tar.gz file"
// @Success 200 {object} map[string]interface{}
// @Security BearerAuth
// @Router /backup/restore [post]
// handleRestore accepts a tar.gz upload and extracts it over the config directory.
func (api *API) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	configDir := filepath.Dir(api.getCfg().ConfigPath)
	if configDir == "" || configDir == "." {
		writeJsonError(w, http.StatusInternalServerError, "Config directory not configured")
		return
	}

	// Limit upload to 50MB
	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)

	if err := r.ParseMultipartForm(50 << 20); err != nil {
		writeJsonError(w, http.StatusBadRequest, "Failed to parse upload: "+err.Error())
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeJsonError(w, http.StatusBadRequest, "No file provided")
		return
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		writeJsonError(w, http.StatusBadRequest, "Invalid gzip file: "+err.Error())
		return
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeJsonError(w, http.StatusBadRequest, "Invalid tar archive: "+err.Error())
			return
		}

		// Prevent path traversal
		cleanName := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
			if header.Typeflag == tar.TypeReg {
				io.Copy(io.Discard, tr)
			}
			continue
		}

		targetPath := filepath.Join(configDir, cleanName)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				writeJsonError(w, http.StatusInternalServerError, "Failed to create directory: "+err.Error())
				return
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				writeJsonError(w, http.StatusInternalServerError, "Failed to create directory: "+err.Error())
				return
			}

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, header.FileInfo().Mode())
			if err != nil {
				// Skip files that can't be overwritten (e.g. running binary)
				log.Warnf("Skipping file during restore (cannot write): %s: %v", cleanName, err)
				// Drain the tar entry so we can continue to the next one
				io.Copy(io.Discard, tr)
				continue
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				log.Warnf("Skipping file during restore (write error): %s: %v", cleanName, err)
				io.Copy(io.Discard, tr)
				continue
			}
			outFile.Close()
		}
	}

	log.Infof("Backup restored successfully to %s", configDir)
	sendResponse(w, map[string]interface{}{
		"success": true,
		"message": "Backup restored successfully",
	})
}

// shouldExcludeFromBackup returns true for files that should not be included in the backup.
func shouldExcludeFromBackup(info os.FileInfo) bool {
	name := info.Name()

	// Exclude geodat files (.dat)
	if strings.HasSuffix(name, ".dat") {
		return true
	}

	// Exclude OUI database
	if name == "oui.txt" {
		return true
	}

	// Exclude executable files
	if !info.IsDir() && info.Mode()&0111 != 0 {
		return true
	}

	// Exclude build output and hidden directories
	if info.IsDir() && (name == "out" || strings.HasPrefix(name, ".")) {
		return true
	}

	return false
}

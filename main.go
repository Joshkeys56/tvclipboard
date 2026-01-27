package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	qrcode "github.com/skip2/go-qrcode"
)

//go:embed static
var staticFiles embed.FS

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Client struct {
	ID     string
	Conn   *websocket.Conn
	Send   chan []byte
	Hub    *Hub
	Mobile bool
}

type Hub struct {
	clients    map[string]*Client
	hostID     string
	broadcast  chan BroadcastMessage
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

type BroadcastMessage struct {
	Message []byte
	From    string // Don't send back to this client
}

type Message struct {
	Type    string `json:"type"`
	Content string `json:"content"`
	From    string `json:"from"`
	Role    string `json:"role,omitempty"`
}

type SessionToken struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
}

type TokenManager struct {
	tokens      map[string]SessionToken
	privateKey  []byte
	timeout     time.Duration
	mu          sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[string]*Client),
		broadcast:  make(chan BroadcastMessage, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

func generatePrivateKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("Failed to generate private key")
	}
	return key
}

func encryptToken(token SessionToken, privateKey []byte) (string, error) {
	jsonData, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(privateKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, jsonData, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decryptToken(encrypted string, privateKey []byte) (SessionToken, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return SessionToken{}, err
	}

	block, err := aes.NewCipher(privateKey)
	if err != nil {
		return SessionToken{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return SessionToken{}, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return SessionToken{}, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return SessionToken{}, err
	}

	var token SessionToken
	if err := json.Unmarshal(plaintext, &token); err != nil {
		return SessionToken{}, err
	}

	return token, nil
}

func NewTokenManager(privateKeyHex string, timeoutMinutes int) *TokenManager {
	var privateKey []byte
	if privateKeyHex != "" {
		key, err := hex.DecodeString(privateKeyHex)
		if err != nil || len(key) != 32 {
			log.Printf("Invalid private key format, generating new one")
			privateKey = generatePrivateKey()
		} else {
			privateKey = key
		}
	} else {
		privateKey = generatePrivateKey()
	}

	timeout := 10 * time.Minute
	if timeoutMinutes > 0 {
		timeout = time.Duration(timeoutMinutes) * time.Minute
	}

	tm := &TokenManager{
		tokens:     make(map[string]SessionToken),
		privateKey: privateKey,
		timeout:    timeout,
	}

	tm.startCleanupRoutine()
	return tm
}

func (tm *TokenManager) GenerateToken() (string, SessionToken, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	token := SessionToken{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
	}

	tm.tokens[token.ID] = token

	encrypted, err := encryptToken(token, tm.privateKey)
	if err != nil {
		return "", SessionToken{}, err
	}

	return encrypted, token, nil
}

func (tm *TokenManager) ValidateToken(encrypted string) (SessionToken, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	token, err := decryptToken(encrypted, tm.privateKey)
	if err != nil {
		return SessionToken{}, fmt.Errorf("invalid token")
	}

	storedToken, ok := tm.tokens[token.ID]
	if !ok {
		return SessionToken{}, fmt.Errorf("token not found")
	}

	if time.Since(storedToken.Timestamp) > tm.timeout {
		return SessionToken{}, fmt.Errorf("token expired")
	}

	return storedToken, nil
}

func (tm *TokenManager) startCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			tm.cleanupExpiredTokens()
		}
	}()
}

func (tm *TokenManager) cleanupExpiredTokens() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for id, token := range tm.tokens {
		if time.Since(token.Timestamp) > tm.timeout {
			delete(tm.tokens, id)
			log.Printf("Cleaned up expired token: %s", id)
		}
	}
}

func hashKey(key string) []byte {
	h := sha256.New()
	h.Write([]byte(key))
	return h.Sum(nil)
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client.ID] = client

			// First client becomes host
			if h.hostID == "" {
				h.hostID = client.ID
				log.Printf("Client %s is now HOST (mobile: %v)", client.ID, client.Mobile)
			} else {
				log.Printf("Client connected: %s (mobile: %v)", client.ID, client.Mobile)
			}

			// Send role assignment to this client
			role := "client"
			if client.ID == h.hostID {
				role = "host"
			}
			roleMsg := Message{Type: "role", Role: role}
			msgBytes, _ := json.Marshal(roleMsg)
			client.Send <- msgBytes

			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client.ID]; ok {
				delete(h.clients, client.ID)
				close(client.Send)

				// If host disconnects, assign new host
				if client.ID == h.hostID {
					h.hostID = ""
					// Assign first remaining client as new host
					for id, c := range h.clients {
						h.hostID = id
						newHostMsg := Message{Type: "role", Role: "host"}
						msgBytes, _ := json.Marshal(newHostMsg)
						c.Send <- msgBytes
						log.Printf("Client %s promoted to HOST", id)
						break
					}
				}

				log.Printf("Client disconnected: %s", client.ID)
			}
			h.mu.Unlock()

		case broadcastMsg := <-h.broadcast:
			h.mu.RLock()
			for id, client := range h.clients {
				// Don't send back to the sender
				if id != broadcastMsg.From {
					select {
					case client.Send <- broadcastMsg.Message:
					default:
						close(client.Send)
						delete(h.clients, id)
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}

func (c *Client) ReadPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			break
		}

		// Parse message
		var msg Message
		if err := json.Unmarshal(message, &msg); err == nil {
			// Broadcast to all other clients (not back to sender)
			msg.From = c.ID
			msgBytes, _ := json.Marshal(msg)
			broadcastMsg := BroadcastMessage{
				Message: msgBytes,
				From:    c.ID,
			}
			c.Hub.broadcast <- broadcastMsg
			log.Printf("Message from %s: %s", c.ID, msg.Content)
		}
	}
}

func (c *Client) WritePump() {
	defer c.Conn.Close()

	for {
		select {
		case message, ok := <-c.Send:
			if !ok {
				return
			}
			c.Conn.WriteMessage(websocket.TextMessage, message)
		}
	}
}

func handleWebSocket(hub *Hub, tm *TokenManager, w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	hub.mu.RLock()
	hostExists := hub.hostID != ""
	hub.mu.RUnlock()

	// Require token for client connections (when host already exists)
	if hostExists {
		if token == "" {
			log.Printf("Connection rejected: no token provided (host exists)")
			http.Error(w, "Token required for connection", http.StatusUnauthorized)
			return
		}

		_, err := tm.ValidateToken(token)
		if err != nil {
			log.Printf("Token validation failed: %v", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
	} else if token != "" {
		// First connection (host) shouldn't have a token
		log.Printf("Connection rejected: token provided for first connection")
		http.Error(w, "Invalid connection - first connection should be from host page", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}

	mobile := r.URL.Query().Get("mobile") == "true"
	client := &Client{
		ID:     uuid.New().String(),
		Conn:   conn,
		Send:   make(chan []byte, 256),
		Hub:    hub,
		Mobile: mobile,
	}

	hub.register <- client

	go client.WritePump()
	go client.ReadPump()
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "localhost"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}

	return "localhost"
}

func main() {
	// Parse environment variables
	privateKeyHex := os.Getenv("TVCLIPBOARD_PRIVATE_KEY")
	timeoutMinutes, _ := strconv.Atoi(os.Getenv("TVCLIPBOARD_SESSION_TIMEOUT"))
	if timeoutMinutes <= 0 {
		timeoutMinutes = 10
	}

	// Initialize components
	hub := NewHub()
	go hub.Run()
	tokenManager := NewTokenManager(privateKeyHex, timeoutMinutes)

	port := "8080"
	localIP := getLocalIP()
	sessionTimeoutSec := int(tokenManager.timeout.Seconds())

	// Template handler for serving HTML
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mode := r.URL.Query().Get("mode")

		var templateFile string
		if mode == "client" {
			templateFile = "client.html"
		} else {
			templateFile = "host.html"
		}

		// Read and serve the template
		content, err := staticFiles.ReadFile("static/" + templateFile)
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		// Inject session timeout as a data attribute
		htmlContent := string(content)
		if mode == "client" {
			htmlContent = injectSessionTimeout(htmlContent, sessionTimeoutSec)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(htmlContent))
	})

	// QR code endpoint
	http.HandleFunc("/qrcode.png", func(w http.ResponseWriter, r *http.Request) {
		// Generate new session token
		encryptedToken, token, err := tokenManager.GenerateToken()
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}
		log.Printf("Generated new session token: %s (expires in %v)", token.ID, tokenManager.timeout)

		// Use the local IP address for the QR code
		host := localIP + ":" + port
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		url := scheme + "://" + host + "?token=" + encryptedToken + "&mode=client"

		png, err := qrcode.Encode(url, qrcode.Medium, 256)
		if err != nil {
			http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
	})

	// WebSocket endpoint
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handleWebSocket(hub, tokenManager, w, r)
	})

	// Serve static files (CSS, JS)
	staticContent, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal("Failed to create sub filesystem:", err)
	}
	fs := http.FileServer(http.FS(staticContent))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Print helpful connection information
	log.Printf("Server starting on port %s\n", port)
	log.Printf("Session timeout: %v minutes\n", timeoutMinutes)
	log.Printf("Local access: http://localhost:%s\n", port)
	if localIP != "localhost" {
		log.Printf("Network access: http://%s:%s\n", localIP, port)
		log.Printf("QR code will use: http://%s:%s?mode=client\n", localIP, port)
	}
	log.Printf("Open in browser and scan QR code with your phone\n")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("Server error:", err)
	}
}

func injectSessionTimeout(html string, timeoutSec int) string {
	tag := `<div class="container" data-session-timeout="` + strconv.Itoa(timeoutSec) + `">`
	oldTag := `<div class="container">`
	return htmlReplace(html, oldTag, tag)
}

func htmlReplace(html, old, new string) string {
	if idx := findSubstring(html, old); idx != -1 {
		return html[:idx] + new + html[idx+len(old):]
	}
	return html
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

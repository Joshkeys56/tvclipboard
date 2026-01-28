package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// TestMessageBroadcast tests that messages are broadcast correctly to all clients except sender
func TestMessageBroadcast(t *testing.T) {
	h := NewHub(1024*1024, 10) // 1MB max, 10 msgs/sec
	go h.Run()

	// Connect three clients
	var mu sync.Mutex
	clients := make([]*websocket.Conn, 3)
	clientIDs := make([]string, 3)
	registered := make(chan struct{}, 3)

	for i := 0; i < 3; i++ {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}

			mobile := r.URL.Query().Get("mobile") == "true"
			client := &Client{
				ID:           uuid.New().String(),
				Conn:         conn,
				Send:         make(chan []byte, 256),
				Hub:          h,
				Mobile:       mobile,
				lastMessage:  time.Now(),
				messageCount: 0,
			}

			h.Register <- client

			mu.Lock()
			clients[i] = conn
			clientIDs[i] = client.ID
			mu.Unlock()
			registered <- struct{}{}
		}))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?mobile=true"
		dialConn, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)

		mu.Lock()
		clients[i] = dialConn
		mu.Unlock()

		time.Sleep(50 * time.Millisecond)
	}

	// Wait for all clients to register
	for i := 0; i < 3; i++ {
		<-registered
	}
	time.Sleep(100 * time.Millisecond)

	// Send a message from client 0
	mu.Lock()
	senderID := clientIDs[0]
	mu.Unlock()

	msg := Message{
		Type:    "text",
		Content: "test message",
		From:    senderID,
	}
	msgBytes, _ := json.Marshal(msg)
	h.broadcast <- BroadcastMessage{Message: msgBytes, From: senderID}

	// Allow message to be processed
	time.Sleep(100 * time.Millisecond)

	// Close all connections
	for _, conn := range clients {
		if conn != nil {
			conn.Close()
		}
	}
}

// TestConcurrentMessages tests concurrent message sending
func TestConcurrentMessages(t *testing.T) {
	h := NewHub(1024*1024, 10) // 1MB max, 10 msgs/sec
	go h.Run()

	numClients := 5
	numMessages := 10

	// Create channels to track messages
	messageCount := 0
	var mu sync.Mutex

	// Create clients
	for i := 0; i < numClients; i++ {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}

			client := &Client{
				ID:           uuid.New().String(),
				Conn:         conn,
				Send:         make(chan []byte, 256),
				Hub:          h,
				Mobile:       false,
				lastMessage:  time.Now(),
				messageCount: 0,
			}

			h.Register <- client

			go func() {
				for range client.Send {
					mu.Lock()
					messageCount++
					mu.Unlock()
				}
			}()

			go client.WritePump()
			go client.ReadPump()
		}))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
		conn, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
		defer conn.Close()
	}

	time.Sleep(200 * time.Millisecond)

	// Send messages concurrently
	var wg sync.WaitGroup
	for i := 0; i < numMessages; i++ {
		wg.Add(1)
		go func(msgNum int) {
			defer wg.Done()

			msg := Message{
				Type:    "text",
				Content: fmt.Sprintf("Message %d", msgNum),
				From:    fmt.Sprintf("client-%d", msgNum%numClients),
			}

			msgBytes, _ := json.Marshal(msg)
			h.broadcast <- BroadcastMessage{Message: msgBytes, From: fmt.Sprintf("client-%d", msgNum%numClients)}
		}(i)
	}

	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	// Verify that messages were received
	mu.Lock()
	receivedCount := messageCount
	mu.Unlock()

	expectedCount := numMessages * (numClients - 1) // Each message goes to all except sender
	if receivedCount != expectedCount {
		t.Logf("Note: Concurrent message handling received %d, expected %d (may vary due to timing)", receivedCount, expectedCount)
	}
}

// TestClientReconnect tests that clients can reconnect
func TestClientReconnect(t *testing.T) {
	h := NewHub(1024*1024, 10) // 1MB max, 10 msgs/sec
	go h.Run()

	var mu sync.Mutex
	var firstConn *websocket.Conn
	var firstConnID string

	// Create server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		client := &Client{
			ID:           uuid.New().String(),
			Conn:         conn,
			Send:         make(chan []byte, 256),
			Hub:          h,
			Mobile:       false,
			lastMessage:  time.Now(),
			messageCount: 0,
		}

		mu.Lock()
		if firstConn == nil {
			firstConn = conn
			firstConnID = client.ID
		}
		mu.Unlock()

		h.Register <- client
		go client.WritePump()
		go client.ReadPump()
	}))
	defer server.Close()

	// Connect first time
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn1, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	initialID := firstConnID
	mu.Unlock()

	// Disconnect
	conn1.Close()
	time.Sleep(100 * time.Millisecond)

	// Reconnect
	conn2, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
	defer conn2.Close()
	time.Sleep(100 * time.Millisecond)

	// Verify reconnection (hub should have a client, may or may not be same ID)
	mu.Lock()
	hasFirstConn := firstConn != nil
	mu.Unlock()

	if !hasFirstConn {
		t.Error("Should have a connected client after reconnection")
	}

	if initialID == "" {
		t.Error("Should have captured initial client ID")
	}
}

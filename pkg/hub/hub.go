package hub

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Client represents a WebSocket client connection
type Client struct {
	ID     string
	Conn   *websocket.Conn
	Send   chan []byte
	Hub    *Hub
	Mobile bool
}

// Hub manages all connected clients
type Hub struct {
	clients    map[string]*Client
	hostID     string
	broadcast  chan BroadcastMessage
	Register   chan *Client
	Unregister chan *Client
	mu         sync.RWMutex
}

// BroadcastMessage represents a message to broadcast to clients
type BroadcastMessage struct {
	Message []byte
	From    string // Don't send back to this client
}

// Message represents a WebSocket message
type Message struct {
	Type    string `json:"type"`
	Content string `json:"content"`
	From    string `json:"from"`
	Role    string `json:"role,omitempty"`
}

// NewHub creates a new Hub
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[string]*Client),
		broadcast:  make(chan BroadcastMessage, 256),
		Register:   make(chan *Client),
		Unregister: make(chan *Client),
	}
}

// Run starts the hub's main loop
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
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

		case client := <-h.Unregister:
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

// ReadPump reads messages from the WebSocket connection
func (c *Client) ReadPump() {
	defer func() {
		c.Hub.Unregister <- c
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

// WritePump writes messages to the WebSocket connection
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

// HostID returns the current host's ID
func (h *Hub) HostID() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.hostID
}

// HasHost returns whether a host has been assigned
func (h *Hub) HasHost() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.hostID != ""
}

// ClientCount returns the number of connected clients
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// SetHostID sets the host ID (for testing only)
func (h *Hub) SetHostID(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hostID = id
}

// GetHostID returns the current host ID (for testing only)
func (h *Hub) GetHostID() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.hostID
}

// NewClient creates a new Client instance
func NewClient(conn *websocket.Conn, hub *Hub, mobile bool) *Client {
	return &Client{
		ID:     uuid.New().String(),
		Conn:   conn,
		Send:   make(chan []byte, 256),
		Hub:    hub,
		Mobile: mobile,
	}
}

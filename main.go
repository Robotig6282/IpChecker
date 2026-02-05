// Minecraft IP Checker - A minimal Minecraft server that displays client IP addresses
//
// This program implements the Minecraft server protocol just enough to:
// 1. Accept incoming connections on port 25565
// 2. Parse the handshake packet to extract protocol version
// 3. Handle status requests (for server list pings)
// 4. Disconnect login attempts with the client's IP address
//
// Protocol reference: https://wiki.vg/Protocol
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"
)

var (
	port       = flag.Int("port", 25565, "TCP port to listen on")
	debug      = flag.Bool("debug", false, "Enable verbose debug logging")
	motdIPShow = flag.Bool("motd-ip-show", false, "Show client IP in MOTD")
)

// Packet IDs for different states
// These IDs are version-independent for the packets we use
const (
	// Handshake packet
	PacketIDHandshake = 0x00

	// Status packets
	PacketIDStatusRequest  = 0x00
	PacketIDStatusResponse = 0x00
	PacketIDStatusPing     = 0x01

	// Login packets
	PacketIDLoginDisconnect = 0x00
)

// HandshakeNextState defines the state after handshake
const (
	NextStateStatus = 1
	NextStateLogin  = 2
)

// Stats tracking
var (
	connCount int64
)

// ============================================================================
// VarInt Encoding/Decoding
// ============================================================================
// Minecraft uses VarInt (variable-length integer) encoding extensively.
// Similar to Protocol Buffers, each byte uses the high bit (0x80) as a
// continuation flag. Max 5 bytes for 32-bit integers.

// readVarInt reads a VarInt from the connection
func readVarInt(conn net.Conn) (int32, error) {
	var result int32
	var numRead int

	for {
		if numRead >= 5 {
			return 0, fmt.Errorf("VarInt too big (>5 bytes)")
		}

		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		if err != nil {
			return 0, err
		}

		b := buf[0]
		result |= int32(b&0x7F) << (7 * uint(numRead))
		numRead++

		// Check continuation bit
		if (b & 0x80) == 0 {
			break
		}
	}

	return result, nil
}

// readVarIntFromSlice reads a VarInt from a byte slice and returns the value
// along with the number of bytes consumed
func readVarIntFromSlice(data []byte) (int32, int, error) {
	var result int32
	var numRead int

	for i, b := range data {
		if numRead >= 5 {
			return 0, 0, fmt.Errorf("VarInt too big (>5 bytes)")
		}

		result |= int32(b&0x7F) << (7 * uint(numRead))
		numRead++

		if (b & 0x80) == 0 {
			return result, i + 1, nil
		}
	}

	return 0, 0, fmt.Errorf("incomplete VarInt")
}

// writeVarInt writes a VarInt to the connection
func writeVarInt(conn net.Conn, value int32) error {
	for {
		temp := byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			temp |= 0x80
		}

		_, err := conn.Write([]byte{temp})
		if err != nil {
			return err
		}

		if value == 0 {
			break
		}
	}
	return nil
}

// ============================================================================
// Minecraft String Encoding/Decoding
// ============================================================================

// readString reads a Minecraft string from the connection
func readString(conn net.Conn) (string, error) {
	length, err := readVarInt(conn)
	if err != nil {
		return "", err
	}

	if length <= 0 {
		return "", nil
	}

	buf := make([]byte, length)
	_, err = conn.Read(buf)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

// ============================================================================
// Packet I/O
// ============================================================================
// Minecraft packets are: VarInt length + VarInt packet ID + payload

// sendPacket sends a packet with length prefix
func sendPacket(conn net.Conn, packetID int32, payload []byte) error {
	// Calculate total length: packet ID (VarInt) + payload
	length := int32(len(payload)) + varIntSize(packetID)

	// Write packet length
	if err := writeVarInt(conn, length); err != nil {
		return err
	}

	// Write packet ID
	if err := writeVarInt(conn, packetID); err != nil {
		return err
	}

	// Write payload
	if len(payload) > 0 {
		_, err := conn.Write(payload)
		return err
	}

	return nil
}

// varIntSize calculates the number of bytes needed to encode a VarInt
func varIntSize(v int32) int32 {
	size := int32(0)
	for {
		v >>= 7
		size++
		if v == 0 {
			break
		}
	}
	return size
}

// readPacketData reads a packet (length prefix already consumed) and returns
// the remaining data after the packet ID
func readPacketData(conn net.Conn, length int32) (int32, []byte, error) {
	if length == 0 {
		return 0, nil, nil
	}

	data := make([]byte, length)
	_, err := conn.Read(data)
	if err != nil {
		return 0, nil, err
	}

	// First field is packet ID (VarInt)
	packetID, bytesRead, err := readVarIntFromSlice(data)
	if err != nil {
		return 0, nil, err
	}

	// Return packet ID and remaining payload
	payload := data[bytesRead:]
	return packetID, payload, nil
}

// ============================================================================
// Minecraft Protocol Structures
// ============================================================================

// Handshake represents the client handshake packet
// Packet ID: 0x00
// Fields:
//   - Protocol Version (VarInt): e.g., 763 = 1.19.3, 764 = 1.20.1, 765 = 1.20.2
//   - Server Address (String): usually "localhost" or the actual server hostname
//   - Server Port (Unsigned Short): client's intended server port (usually 25565)
//   - Next State (VarInt): 1 = status, 2 = login
type Handshake struct {
	ProtocolVersion int32
	ServerAddress   string
	ServerPort      uint16
	NextState       int32
}

// StatusResponse represents the JSON response to a status request
type StatusResponse struct {
	Version struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
	} `json:"version"`
	Players struct {
		Max    int `json:"max"`
		Online int `json:"online"`
	} `json:"players"`
	Description struct {
		Text string `json:"text"`
	} `json:"description"`
}

// ============================================================================
// Protocol Handlers
// ============================================================================

// handleHandshake reads and parses the handshake packet
// This is always the first packet sent by the client
func handleHandshake(conn net.Conn) (*Handshake, error) {
	// Read packet length
	length, err := readVarInt(conn)
	if err != nil {
		return nil, fmt.Errorf("read packet length: %w", err)
	}

	// Read packet data
	packetID, payload, err := readPacketData(conn, length)
	if err != nil {
		return nil, fmt.Errorf("read packet data: %w", err)
	}

	if packetID != PacketIDHandshake {
		return nil, fmt.Errorf("expected handshake packet (0x00), got 0x%02x", packetID)
	}

	// Parse handshake fields from payload
	offset := 0

	// Protocol Version (VarInt)
	protocolVersion, bytesRead, err := readVarIntFromSlice(payload[offset:])
	if err != nil {
		return nil, fmt.Errorf("read protocol version: %w", err)
	}
	offset += bytesRead

	// Server Address (String: VarInt length + UTF-8 bytes)
	addrLen, bytesRead, err := readVarIntFromSlice(payload[offset:])
	if err != nil {
		return nil, fmt.Errorf("read server address length: %w", err)
	}
	offset += bytesRead

	if addrLen < 0 || int(addrLen) > len(payload[offset:]) {
		return nil, fmt.Errorf("invalid server address length: %d", addrLen)
	}

	serverAddress := string(payload[offset : offset+int(addrLen)])
	offset += int(addrLen)

	// Server Port (Unsigned Short, 2 bytes, big-endian)
	if offset+2 > len(payload) {
		return nil, fmt.Errorf("not enough data for server port")
	}
	serverPort := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	// Next State (VarInt)
	nextState, _, err := readVarIntFromSlice(payload[offset:])
	if err != nil {
		return nil, fmt.Errorf("read next state: %w", err)
	}

	return &Handshake{
		ProtocolVersion: protocolVersion,
		ServerAddress:   serverAddress,
		ServerPort:      serverPort,
		NextState:       nextState,
	}, nil
}

// handleStatus handles the status state (server list ping)
// Client sends Request (0x00), we respond with Response (0x00)
// Client then sends Ping (0x01), we respond with Pong (0x01)
func handleStatus(conn net.Conn) error {
	// Set read deadline for status operations
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read status request packet
	length, err := readVarInt(conn)
	if err != nil {
		return fmt.Errorf("read request length: %w", err)
	}

	packetID, _, err := readPacketData(conn, length)
	if err != nil {
		return fmt.Errorf("read request data: %w", err)
	}

	if packetID != PacketIDStatusRequest {
		return fmt.Errorf("expected status request (0x00), got 0x%02x", packetID)
	}

	// Build status response JSON
	status := StatusResponse{}
	status.Version.Name = "IP Checker"
	status.Version.Protocol = 0 // We're version-agnostic
	status.Players.Max = 0
	status.Players.Online = 0

	// Set MOTD - optionally include client IP
	if *motdIPShow {
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			host = conn.RemoteAddr().String()
		}
		status.Description.Text = fmt.Sprintf("IP Checker Server\nYour IP: %s", host)
	} else {
		status.Description.Text = "IP Checker Server"
	}

	jsonData, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("marshal status JSON: %w", err)
	}

	// Send status response (packet ID 0x00 + JSON string)
	// JSON string is encoded as: VarInt length + UTF-8 bytes
	jsonStr := string(jsonData)
	payload := make([]byte, 0, len(jsonStr)+5)

	// Encode JSON string length as VarInt
	jsonLen := int32(len(jsonStr))
	for {
		temp := byte(jsonLen & 0x7F)
		jsonLen >>= 7
		if jsonLen != 0 {
			temp |= 0x80
		}
		payload = append(payload, temp)
		if jsonLen == 0 {
			break
		}
	}

	// Append JSON string bytes
	payload = append(payload, jsonData...)

	if err := sendPacket(conn, PacketIDStatusResponse, payload); err != nil {
		return fmt.Errorf("send status response: %w", err)
	}

	// Read ping packet (0x01) with payload (8 bytes, big-endian long)
	length, err = readVarInt(conn)
	if err != nil {
		return fmt.Errorf("read ping length: %w", err)
	}

	packetID, pingData, err := readPacketData(conn, length)
	if err != nil {
		return fmt.Errorf("read ping data: %w", err)
	}

	if packetID != PacketIDStatusPing {
		// Client might disconnect after receiving status, that's OK
		return nil
	}

	// Send pong response (same packet ID and payload)
	if err := sendPacket(conn, PacketIDStatusPing, pingData); err != nil {
		return fmt.Errorf("send pong: %w", err)
	}

	return nil
}

// sendLoginDisconnect sends a disconnect packet during the login state
// Format: packet ID (0x00) + JSON reason string (VarInt length + UTF-8)
func sendLoginDisconnect(conn net.Conn, reason string) error {
	// Build JSON string
	jsonReason := fmt.Sprintf(`{"text":"%s"}`, reason)

	// Encode as Minecraft string: VarInt length + UTF-8 bytes
	payload := make([]byte, 0, len(jsonReason)+5)

	// Length prefix
	strLen := int32(len(jsonReason))
	for {
		temp := byte(strLen & 0x7F)
		strLen >>= 7
		if strLen != 0 {
			temp |= 0x80
		}
		payload = append(payload, temp)
		if strLen == 0 {
			break
		}
	}

	// String bytes
	payload = append(payload, []byte(jsonReason)...)

	return sendPacket(conn, PacketIDLoginDisconnect, payload)
}

// handleLogin handles the login state
// We immediately disconnect with the client's IP and protocol info
func handleLogin(conn net.Conn, protocolVersion int32) error {
	// Extract IP without port
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}

	// Build disconnect message
	disconnectMsg := fmt.Sprintf("Your IP: %s | Protocol: %d", host, protocolVersion)

	if err := sendLoginDisconnect(conn, disconnectMsg); err != nil {
		return fmt.Errorf("send login disconnect: %w", err)
	}

	return nil
}

// ============================================================================
// Main Connection Handler
// ============================================================================

// handleConnection handles a single client connection
func handleConnection(conn net.Conn) {
	connID := atomic.AddInt64(&connCount, 1)
	if *debug {
		log.Printf("[%d] New connection from %s", connID, conn.RemoteAddr())
	}

	// Set overall timeout for the connection
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	defer func() {
		conn.Close()
		if *debug {
			log.Printf("[%d] Connection closed", connID)
		}
	}()

	// Always start with handshake
	handshake, err := handleHandshake(conn)
	if err != nil {
		if *debug {
			log.Printf("[%d] Handshake error: %v", connID, err)
		}
		return
	}

	if *debug {
		log.Printf("[%d] Handshake: protocol=%d, address=%s, port=%d, nextState=%d",
			connID, handshake.ProtocolVersion, handshake.ServerAddress,
			handshake.ServerPort, handshake.NextState)
	}

	// Handle based on next state
	switch handshake.NextState {
	case NextStateStatus:
		if err := handleStatus(conn); err != nil {
			if *debug {
				log.Printf("[%d] Status handling error: %v", connID, err)
			}
		} else {
			if *debug {
				log.Printf("[%d] Status request completed", connID)
			}
		}

	case NextStateLogin:
		host, _, addrErr := net.SplitHostPort(conn.RemoteAddr().String())
		if addrErr != nil {
			host = conn.RemoteAddr().String()
		}

		if err := handleLogin(conn, handshake.ProtocolVersion); err != nil {
			log.Printf("[%d] Login from %s (protocol %d) - error: %v", connID, host, handshake.ProtocolVersion, err)
		} else {
			log.Printf("[%d] Login from %s (protocol %d)", connID, host, handshake.ProtocolVersion)
		}

	default:
		if *debug {
			log.Printf("[%d] Invalid next state: %d", connID, handshake.NextState)
		}
	}
}

// ============================================================================
// Main
// ============================================================================

func main() {
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	defer listener.Close()

	log.Printf("Minecraft IP Checker listening on %s", addr)
	if !*debug {
		log.Printf("Quiet mode - use -debug for verbose logging")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		// Handle each connection in a goroutine
		go handleConnection(conn)
	}
}

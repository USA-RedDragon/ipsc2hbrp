package hbrp

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/USA-RedDragon/ipsc2hbrp/internal/config"
	"github.com/USA-RedDragon/ipsc2hbrp/internal/hbrp/proto"
)

func testHBRPConfig() *config.Config {
	return &config.Config{
		HBRP: config.HBRP{
			ID:          311860,
			Callsign:    "N0CALL",
			RXFreq:      449000000,
			TXFreq:      444000000,
			TXPower:     50,
			ColorCode:   1,
			Latitude:    35.0,
			Longitude:   -97.0,
			Height:      30,
			Location:    "Oklahoma",
			Description: "Test Repeater",
			URL:         "https://example.com",
			Password:    "s3cret",
		},
	}
}

// newTestClient creates an HBRPClient with a buffered connTX channel
// so packet-building methods can be tested without a real connection.
func newTestClient(t *testing.T) *HBRPClient {
	t.Helper()
	cfg := testHBRPConfig()
	client := &HBRPClient{
		config:  cfg,
		connTX:  make(chan []byte, 16),
		tx_chan: make(chan proto.Packet, 16),
		done:    make(chan struct{}),
	}
	client.state.Store(uint32(STATE_IDLE))
	return client
}

func TestStateConstants(t *testing.T) {
	t.Parallel()
	if STATE_IDLE != 0 {
		t.Fatalf("expected STATE_IDLE=0, got %d", STATE_IDLE)
	}
	if STATE_SENT_LOGIN != 1 {
		t.Fatalf("expected STATE_SENT_LOGIN=1, got %d", STATE_SENT_LOGIN)
	}
	if STATE_SENT_AUTH != 2 {
		t.Fatalf("expected STATE_SENT_AUTH=2, got %d", STATE_SENT_AUTH)
	}
	if STATE_SENT_RPTC != 3 {
		t.Fatalf("expected STATE_SENT_RPTC=3, got %d", STATE_SENT_RPTC)
	}
	if STATE_READY != 4 {
		t.Fatalf("expected STATE_READY=4, got %d", STATE_READY)
	}
	if STATE_TIMEOUT != 5 {
		t.Fatalf("expected STATE_TIMEOUT=5, got %d", STATE_TIMEOUT)
	}
}

func TestNewHBRPClient(t *testing.T) {
	t.Parallel()
	cfg := testHBRPConfig()
	client := NewHBRPClient(cfg)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.config != cfg {
		t.Fatal("expected config to be set")
	}
	if client.started.Load() {
		t.Fatal("expected started=false")
	}
	if client.state.Load() != uint32(STATE_IDLE) {
		t.Fatalf("expected STATE_IDLE, got %d", client.state.Load())
	}
	if client.keepAlive.Seconds() != 5 {
		t.Fatalf("expected 5s keepalive, got %v", client.keepAlive)
	}
	if client.timeout.Seconds() != 15 {
		t.Fatalf("expected 15s timeout, got %v", client.timeout)
	}
	if client.translator == nil {
		t.Fatal("expected non-nil translator")
	}
}

func TestSendLoginPacket(t *testing.T) {
	t.Parallel()
	client := newTestClient(t)
	client.sendLogin()

	data := <-client.connTX
	// Should start with "RPTL"
	if string(data[:4]) != "RPTL" {
		t.Fatalf("expected RPTL prefix, got %q", string(data[:4]))
	}
	// Should contain the hex ID
	hexID := fmt.Sprintf("%08x", client.config.HBRP.ID)
	if string(data[4:12]) != hexID {
		t.Fatalf("expected hex ID %q, got %q", hexID, string(data[4:12]))
	}
	// Total length = 4 (RPTL) + 8 (hex ID)
	if len(data) != 12 {
		t.Fatalf("expected 12 bytes, got %d", len(data))
	}
}

func TestSendRPTCLPacket(t *testing.T) {
	t.Parallel()
	client := newTestClient(t)
	client.sendRPTCL()

	data := <-client.connTX
	if string(data[:5]) != "RPTCL" {
		t.Fatalf("expected RPTCL prefix, got %q", string(data[:5]))
	}
	hexID := fmt.Sprintf("%08x", client.config.HBRP.ID)
	if string(data[5:13]) != hexID {
		t.Fatalf("expected hex ID %q, got %q", hexID, string(data[5:13]))
	}
	if len(data) != 13 {
		t.Fatalf("expected 13 bytes, got %d", len(data))
	}
}

func TestSendRPTCPacket(t *testing.T) {
	t.Parallel()
	client := newTestClient(t)
	client.sendRPTC()

	data := <-client.connTX
	// Should start with "RPTC"
	if string(data[:4]) != "RPTC" {
		t.Fatalf("expected RPTC prefix, got %q", string(data[:4]))
	}

	// Check callsign (8 bytes, left-justified)
	callsign := string(data[4:12])
	if !strings.HasPrefix(callsign, "N0CALL") {
		t.Fatalf("expected callsign starting with N0CALL, got %q", callsign)
	}

	// Check hex radio ID (8 bytes)
	hexID := fmt.Sprintf("%08x", client.config.HBRP.ID)
	if string(data[12:20]) != hexID {
		t.Fatalf("expected hex ID %q at offset 12, got %q", hexID, string(data[12:20]))
	}

	// Check RX freq (9 bytes)
	expectedRX := fmt.Sprintf("%09d", client.config.HBRP.RXFreq)
	if string(data[20:29]) != expectedRX {
		t.Fatalf("expected RX freq %q, got %q", expectedRX, string(data[20:29]))
	}

	// Check TX freq (9 bytes)
	expectedTX := fmt.Sprintf("%09d", client.config.HBRP.TXFreq)
	if string(data[29:38]) != expectedTX {
		t.Fatalf("expected TX freq %q, got %q", expectedTX, string(data[29:38]))
	}

	// Check TX power (2 bytes)
	expectedPower := fmt.Sprintf("%02d", client.config.HBRP.TXPower)
	if string(data[38:40]) != expectedPower {
		t.Fatalf("expected TX power %q, got %q", expectedPower, string(data[38:40]))
	}

	// Check color code (2 bytes)
	expectedCC := fmt.Sprintf("%02d", client.config.HBRP.ColorCode)
	if string(data[40:42]) != expectedCC {
		t.Fatalf("expected color code %q, got %q", expectedCC, string(data[40:42]))
	}
}

func TestSendRPTKPacket(t *testing.T) {
	t.Parallel()
	client := newTestClient(t)
	random := []byte("12345678")
	client.sendRPTK(random)

	data := <-client.connTX
	// Should start with "RPTK"
	if string(data[:4]) != "RPTK" {
		t.Fatalf("expected RPTK prefix, got %q", string(data[:4]))
	}

	// Hex ID at offset 4
	hexID := fmt.Sprintf("%08x", client.config.HBRP.ID)
	if string(data[4:12]) != hexID {
		t.Fatalf("expected hex ID %q, got %q", hexID, string(data[4:12]))
	}

	// Token at offset 12 should be 64 hex characters (sha256)
	token := string(data[12:76])
	if len(token) != 64 {
		t.Fatalf("expected 64-char token, got %d", len(token))
	}

	// Verify the token is the correct sha256(random + password)
	s256 := sha256.New()
	s256.Write(random)
	s256.Write([]byte(client.config.HBRP.Password))
	expectedToken := fmt.Sprintf("%x", s256.Sum(nil))
	if token != expectedToken {
		t.Fatalf("expected token %q, got %q", expectedToken, token)
	}

	// Total length = 4 (RPTK) + 8 (hex ID) + 64 (token)
	if len(data) != 76 {
		t.Fatalf("expected 76 bytes, got %d", len(data))
	}
}

func TestSendPingPacket(t *testing.T) {
	t.Parallel()
	client := newTestClient(t)
	client.sendPing()

	data := <-client.connTX
	if string(data[:7]) != "MSTPING" {
		t.Fatalf("expected MSTPING prefix, got %q", string(data[:7]))
	}
	hexID := fmt.Sprintf("%08x", client.config.HBRP.ID)
	if string(data[7:15]) != hexID {
		t.Fatalf("expected hex ID %q, got %q", hexID, string(data[7:15]))
	}
	if len(data) != 15 {
		t.Fatalf("expected 15 bytes, got %d", len(data))
	}
}

func TestSendPacketEncodesAndSends(t *testing.T) {
	t.Parallel()
	client := newTestClient(t)
	pkt := proto.Packet{
		Signature:   "DMRD",
		Seq:         1,
		Src:         100,
		Dst:         200,
		Repeater:    3001,
		Slot:        true,
		GroupCall:   true,
		FrameType:   0,
		DTypeOrVSeq: 0,
		StreamID:    0x1234,
	}
	client.sendPacket(pkt)

	data := <-client.connTX
	if len(data) != 53 {
		t.Fatalf("expected 53 bytes, got %d", len(data))
	}
	if string(data[:4]) != "DMRD" {
		t.Fatalf("expected DMRD prefix, got %q", string(data[:4]))
	}
}

func TestSetIPSCHandler(t *testing.T) {
	t.Parallel()
	client := newTestClient(t)
	if client.ipscHandler != nil {
		t.Fatal("expected nil handler initially")
	}
	called := false
	client.SetIPSCHandler(func(data []byte) {
		called = true
	})
	if client.ipscHandler == nil {
		t.Fatal("expected non-nil handler after SetIPSCHandler")
	}
	client.ipscHandler([]byte{})
	if !called {
		t.Fatal("expected handler to be called")
	}
}

func TestPacketTypeMstack(t *testing.T) {
	t.Parallel()
	if packetTypeMstack != "MSTACK" {
		t.Fatalf("expected packetTypeMstack=%q, got %q", "MSTACK", packetTypeMstack)
	}
}

func TestSendLoginHexIDFormat(t *testing.T) {
	t.Parallel()
	// Test with ID=1 to verify zero-padding
	cfg := testHBRPConfig()
	cfg.HBRP.ID = 1
	client := &HBRPClient{
		config: cfg,
		connTX: make(chan []byte, 16),
	}
	client.sendLogin()

	data := <-client.connTX
	hexID := string(data[4:12])
	if hexID != "00000001" {
		t.Fatalf("expected zero-padded hex ID %q, got %q", "00000001", hexID)
	}
}

func TestSendRPTKDifferentRandomProducesDifferentToken(t *testing.T) {
	t.Parallel()
	client := newTestClient(t)

	client.sendRPTK([]byte("aaaaaaaa"))
	data1 := <-client.connTX
	token1 := string(data1[12:76])

	client.sendRPTK([]byte("bbbbbbbb"))
	data2 := <-client.connTX
	token2 := string(data2[12:76])

	if token1 == token2 {
		t.Fatal("expected different tokens for different random data")
	}
}

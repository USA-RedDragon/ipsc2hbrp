package ipsc

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/USA-RedDragon/ipsc2hbrp/internal/config"
)

func testConfig(authEnabled bool, authKey string) *config.Config {
	return &config.Config{
		HBRP: config.HBRP{
			ID: 311860,
		},
		IPSC: config.IPSC{
			Auth: config.IPSCAuth{
				Enabled: authEnabled,
				Key:     authKey,
			},
		},
	}
}

func TestParsePeerID(t *testing.T) {
	t.Parallel()
	data := make([]byte, 5)
	binary.BigEndian.PutUint32(data[1:5], 12345)
	id, err := parsePeerID(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 12345 {
		t.Fatalf("expected 12345, got %d", id)
	}
}

func TestParsePeerIDTooShort(t *testing.T) {
	t.Parallel()
	_, err := parsePeerID([]byte{0x90, 0x00})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestParsePeerIDMaxValue(t *testing.T) {
	t.Parallel()
	data := []byte{0x90, 0xFF, 0xFF, 0xFF, 0xFF}
	id, err := parsePeerID(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 0xFFFFFFFF {
		t.Fatalf("expected 0xFFFFFFFF, got %d", id)
	}
}

func TestUint16ToBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		val    uint16
		expect [2]byte
	}{
		{0, [2]byte{0, 0}},
		{1, [2]byte{0, 1}},
		{0xFF00, [2]byte{0xFF, 0x00}},
		{0xBEEF, [2]byte{0xBE, 0xEF}},
	}
	for _, tt := range tests {
		b := uint16ToBytes(tt.val)
		if b[0] != tt.expect[0] || b[1] != tt.expect[1] {
			t.Errorf("uint16ToBytes(%d) = %v, want %v", tt.val, b, tt.expect)
		}
	}
}

func TestUint32ToBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		val    uint32
		expect [4]byte
	}{
		{0, [4]byte{0, 0, 0, 0}},
		{1, [4]byte{0, 0, 0, 1}},
		{0xDEADBEEF, [4]byte{0xDE, 0xAD, 0xBE, 0xEF}},
	}
	for _, tt := range tests {
		b := uint32ToBytes(tt.val)
		if b[0] != tt.expect[0] || b[1] != tt.expect[1] || b[2] != tt.expect[2] || b[3] != tt.expect[3] {
			t.Errorf("uint32ToBytes(%d) = %v, want %v", tt.val, b, tt.expect)
		}
	}
}

func TestCloneUDPAddrNil(t *testing.T) {
	t.Parallel()
	if cloneUDPAddr(nil) != nil {
		t.Fatal("expected nil for nil input")
	}
}

func TestCloneUDPAddr(t *testing.T) {
	t.Parallel()
	orig := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234, Zone: "eth0"}
	clone := cloneUDPAddr(orig)

	if !clone.IP.Equal(orig.IP) || clone.Port != orig.Port || clone.Zone != orig.Zone {
		t.Fatalf("clone mismatch: orig=%v clone=%v", orig, clone)
	}

	// Mutating the clone must not affect the original.
	clone.IP[0] = 99
	if orig.IP[0] == 99 {
		t.Fatal("clone shares underlying IP slice with original")
	}
}

func TestCloneUDPAddrNilIP(t *testing.T) {
	t.Parallel()
	orig := &net.UDPAddr{Port: 5678}
	clone := cloneUDPAddr(orig)
	if clone.IP != nil {
		t.Fatalf("expected nil IP, got %v", clone.IP)
	}
	if clone.Port != 5678 {
		t.Fatalf("expected port 5678, got %d", clone.Port)
	}
}

func TestAuth(t *testing.T) {
	t.Parallel()
	key := "0000000000000000000000000000000000001234"
	cfg := testConfig(true, "1234")
	s := NewIPSCServer(cfg)

	payload := []byte("hello world")
	h := hmac.New(sha1.New, mustDecodeHex(t, key))
	h.Write(payload)
	hash := h.Sum(nil)[:10]
	data := make([]byte, 0, len(payload)+len(hash))
	data = append(data, payload...)
	data = append(data, hash...)

	if !s.auth(data) {
		t.Fatal("expected auth to pass")
	}
}

func TestAuthBadHash(t *testing.T) {
	t.Parallel()
	cfg := testConfig(true, "1234")
	s := NewIPSCServer(cfg)

	payload := []byte("hello world")
	bad := make([]byte, 10)
	data := make([]byte, 0, len(payload)+len(bad))
	data = append(data, payload...)
	data = append(data, bad...)

	if s.auth(data) {
		t.Fatal("expected auth to fail with bad hash")
	}
}

func mustDecodeHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	b := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		var val byte
		for j := 0; j < 2; j++ {
			c := hexStr[i+j]
			switch {
			case c >= '0' && c <= '9':
				val = val*16 + (c - '0')
			case c >= 'a' && c <= 'f':
				val = val*16 + (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				val = val*16 + (c - 'A' + 10)
			}
		}
		b[i/2] = val
	}
	return b
}

func TestNewIPSCServerNoAuth(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)
	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if s.authKey != nil {
		t.Fatal("expected nil auth key when auth disabled")
	}
	if s.localID != cfg.HBRP.ID {
		t.Fatalf("expected localID %d, got %d", cfg.HBRP.ID, s.localID)
	}
}

func TestNewIPSCServerWithAuth(t *testing.T) {
	t.Parallel()
	cfg := testConfig(true, "ABCD")
	s := NewIPSCServer(cfg)
	if s.authKey == nil {
		t.Fatal("expected non-nil auth key")
	}
	if len(s.authKey) != 20 {
		t.Fatalf("expected 20-byte auth key, got %d", len(s.authKey))
	}
}

func TestDefaultModeByte(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)
	mode := s.defaultModeByte()
	// Should have operational, digital, ts1, ts2 bits
	if mode&0b01000000 == 0 {
		t.Fatal("expected peerOperational bit set")
	}
	if mode&0b00100000 == 0 {
		t.Fatal("expected peerDigital bit set")
	}
	if mode&0b00001000 == 0 {
		t.Fatal("expected ts1On bit set")
	}
	if mode&0b00000010 == 0 {
		t.Fatal("expected ts2On bit set")
	}
}

func TestDefaultFlagsBytesNoAuth(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)
	flags := s.defaultFlagsBytes()
	if flags[3]&0x10 != 0 {
		t.Fatal("expected auth flag clear when auth disabled")
	}
	if flags[3]&0x0D != 0x0D {
		t.Fatalf("expected base flags 0x0D, got %02X", flags[3])
	}
}

func TestDefaultFlagsBytesWithAuth(t *testing.T) {
	t.Parallel()
	cfg := testConfig(true, "1234")
	s := NewIPSCServer(cfg)
	flags := s.defaultFlagsBytes()
	if flags[3]&0x10 == 0 {
		t.Fatal("expected auth flag set when auth enabled")
	}
}

func TestBuildMasterRegisterReply(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)
	reply := s.buildMasterRegisterReply()

	if reply[0] != byte(PacketType_MasterRegisterReply) {
		t.Fatalf("expected packet type 0x%02X, got 0x%02X", PacketType_MasterRegisterReply, reply[0])
	}

	id := binary.BigEndian.Uint32(reply[1:5])
	if id != cfg.HBRP.ID {
		t.Fatalf("expected ID %d, got %d", cfg.HBRP.ID, id)
	}
}

func TestBuildMasterAliveReply(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)
	reply := s.buildMasterAliveReply()

	if reply[0] != byte(PacketType_MasterAliveReply) {
		t.Fatalf("expected packet type 0x%02X, got 0x%02X", PacketType_MasterAliveReply, reply[0])
	}
}

func TestBuildPeerListReplyEmpty(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)
	reply := s.buildPeerListReply()

	if reply[0] != byte(PacketType_PeerListReply) {
		t.Fatalf("expected packet type 0x%02X, got 0x%02X", PacketType_PeerListReply, reply[0])
	}

	// Peer count should be 0
	peerCount := binary.BigEndian.Uint16(reply[5:7])
	if peerCount != 0 {
		t.Fatalf("expected 0 peers, got %d", peerCount)
	}
}

func TestBuildPeerListReplyWithPeers(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)

	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 50000}
	s.upsertPeer(42, addr, 0x6A, [4]byte{0, 0, 0, 0x0D})

	reply := s.buildPeerListReply()
	if reply[0] != byte(PacketType_PeerListReply) {
		t.Fatalf("expected packet type 0x%02X, got 0x%02X", PacketType_PeerListReply, reply[0])
	}

	// Should have at least the peer entry bytes after the header
	if len(reply) < 7+11 {
		t.Fatalf("reply too short for 1 peer: %d bytes", len(reply))
	}
}

func TestUpsertPeerAndCount(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)

	if s.peerCount() != 0 {
		t.Fatalf("expected 0 peers initially, got %d", s.peerCount())
	}

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	s.upsertPeer(100, addr, 0x6A, [4]byte{})

	if s.peerCount() != 1 {
		t.Fatalf("expected 1 peer, got %d", s.peerCount())
	}

	// Upsert same peer should not increase count
	s.upsertPeer(100, addr, 0x6A, [4]byte{})
	if s.peerCount() != 1 {
		t.Fatalf("expected still 1 peer after upsert, got %d", s.peerCount())
	}

	// Add a different peer
	addr2 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5678}
	s.upsertPeer(200, addr2, 0x6A, [4]byte{})
	if s.peerCount() != 2 {
		t.Fatalf("expected 2 peers, got %d", s.peerCount())
	}
}

func TestMarkPeerAlive(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	s.markPeerAlive(100, addr)

	if s.peerCount() != 1 {
		t.Fatalf("expected 1 peer after markPeerAlive, got %d", s.peerCount())
	}

	// Mark alive again should increment keepalive counter
	s.markPeerAlive(100, addr)
	s.mu.RLock()
	peer := s.peers[100]
	keepAlive := peer.KeepAliveReceived
	s.mu.RUnlock()

	if keepAlive != 2 {
		t.Fatalf("expected 2 keepalives, got %d", keepAlive)
	}
}

func TestHandlePacketTooShort(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}

	_, err := s.handlePacket([]byte{}, addr)
	if err == nil {
		t.Fatal("expected error on empty packet")
	}
}

func TestHandlePacketUnknownType(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}

	data := []byte{0xFF, 0, 0, 0, 1}
	_, err := s.handlePacket(data, addr)
	if err == nil {
		t.Fatal("expected error for unknown packet type 0xFF")
	}
}

func TestHandlePacketReplyTypesIgnored(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}

	replyTypes := []byte{
		byte(PacketType_MasterRegisterReply),
		byte(PacketType_PeerListReply),
		byte(PacketType_MasterAliveReply),
	}
	for _, pt := range replyTypes {
		data := make([]byte, 5)
		data[0] = pt
		_, err := s.handlePacket(data, addr)
		if !errors.Is(err, ErrPacketIgnored) {
			t.Fatalf("expected ErrPacketIgnored for type 0x%02X, got %v", pt, err)
		}
	}
}

func TestPacketTypeValues(t *testing.T) {
	t.Parallel()
	// Verify the packet type constants match the IPSC protocol
	expected := map[PacketType]byte{
		PacketType_GroupVoice:            0x80,
		PacketType_PrivateVoice:          0x81,
		PacketType_GroupData:             0x83,
		PacketType_PrivateData:           0x84,
		PacketType_RepeaterWakeUp:        0x85,
		PacketType_MasterRegisterRequest: 0x90,
		PacketType_MasterRegisterReply:   0x91,
		PacketType_PeerListRequest:       0x92,
		PacketType_PeerListReply:         0x93,
		PacketType_MasterAliveRequest:    0x96,
		PacketType_MasterAliveReply:      0x97,
	}
	for pt, val := range expected {
		if byte(pt) != val {
			t.Errorf("PacketType %v: expected 0x%02X, got 0x%02X", pt, val, byte(pt))
		}
	}
}

func TestUpsertPeerRegistrationStatus(t *testing.T) {
	t.Parallel()
	cfg := testConfig(false, "")
	s := NewIPSCServer(cfg)

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	s.upsertPeer(100, addr, 0x6A, [4]byte{})

	s.mu.RLock()
	peer := s.peers[100]
	registered := peer.RegistrationStatus
	lastSeen := peer.LastSeen
	s.mu.RUnlock()

	if !registered {
		t.Fatal("expected peer to be registered")
	}
	if time.Since(lastSeen) > time.Second {
		t.Fatal("expected LastSeen to be recent")
	}
}

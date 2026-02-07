package ipsc

import (
	"encoding/binary"
	"testing"

	hbrp "github.com/USA-RedDragon/ipsc2hbrp/internal/hbrp/proto"
)

func newTestTranslator(t *testing.T) *IPSCTranslator {
	t.Helper()
	tr, err := NewIPSCTranslator()
	if err != nil {
		t.Fatalf("NewIPSCTranslator() error: %v", err)
	}
	tr.SetPeerID(12345)
	return tr
}

func TestNewIPSCTranslator(t *testing.T) {
	t.Parallel()
	tr, err := NewIPSCTranslator()
	if err != nil {
		t.Fatalf("NewIPSCTranslator() error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil translator")
	}
	if tr.streams == nil {
		t.Fatal("expected non-nil streams map")
	}
	if tr.reverseStreams == nil {
		t.Fatal("expected non-nil reverseStreams map")
	}
}

func TestSetPeerID(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	if tr.peerID != 12345 {
		t.Fatalf("expected peerID 12345, got %d", tr.peerID)
	}
	if tr.repeaterID != 12345 {
		t.Fatalf("expected repeaterID 12345, got %d", tr.repeaterID)
	}
}

func TestCleanupStream(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)

	// Create some stream state by translating a voice header
	pkt := makeTestHBRPPacket(true, true, hbrpFrameTypeDataSync, 1) // VoiceLCHeader=1
	tr.TranslateToIPSC(pkt)

	streamID := uint32(pkt.StreamID) //nolint:gosec // test value is within uint32 range

	tr.mu.Lock()
	_, exists := tr.streams[streamID]
	tr.mu.Unlock()

	if !exists {
		t.Fatal("expected stream state to exist after translate")
	}

	tr.CleanupStream(streamID)

	tr.mu.Lock()
	_, exists = tr.streams[streamID]
	tr.mu.Unlock()

	if exists {
		t.Fatal("expected stream state to be removed after cleanup")
	}
}

func makeTestHBRPPacket(groupCall, slot bool, frameType, dtypeOrVSeq uint) hbrp.Packet {
	return hbrp.Packet{
		Signature:   "DMRD",
		Seq:         0,
		Src:         100,
		Dst:         200,
		Repeater:    3001,
		Slot:        slot,
		GroupCall:   groupCall,
		FrameType:   frameType,
		DTypeOrVSeq: dtypeOrVSeq,
		StreamID:    0x1234,
		DMRData:     [33]byte{},
	}
}

func TestTranslateToIPSCNilOnUnknownFrameType(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	pkt := makeTestHBRPPacket(true, false, 3, 0) // frameType=3 is unknown
	result := tr.TranslateToIPSC(pkt)
	if result != nil {
		t.Fatalf("expected nil for unknown frame type, got %d packets", len(result))
	}
}

func TestTranslateToIPSCVoiceHeaderProduces3Packets(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	// DataTypeVoiceLCHeader = 1
	pkt := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 1)
	result := tr.TranslateToIPSC(pkt)
	if len(result) != 3 {
		t.Fatalf("expected 3 voice header packets, got %d", len(result))
	}
}

func TestTranslateToIPSCVoiceTerminator(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	// First send a header to establish stream
	header := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 1)
	tr.TranslateToIPSC(header)

	// DataTypeTerminatorWithLC = 2
	term := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 2)
	term.StreamID = header.StreamID
	result := tr.TranslateToIPSC(term)
	if len(result) != 1 {
		t.Fatalf("expected 1 terminator packet, got %d", len(result))
	}
}

func TestTranslateToIPSCGroupCallFlag(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)

	// Group call
	pkt := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 1)
	result := tr.TranslateToIPSC(pkt)
	if len(result) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	if result[0][0] != 0x80 {
		t.Fatalf("expected group voice type 0x80, got 0x%02X", result[0][0])
	}

	// Private call
	tr2 := newTestTranslator(t)
	pkt2 := makeTestHBRPPacket(false, false, hbrpFrameTypeDataSync, 1)
	pkt2.StreamID = 0x5678
	result2 := tr2.TranslateToIPSC(pkt2)
	if len(result2) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	if result2[0][0] != 0x81 {
		t.Fatalf("expected private voice type 0x81, got 0x%02X", result2[0][0])
	}
}

func TestTranslateToIPSCPeerIDInHeader(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	pkt := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 1)
	result := tr.TranslateToIPSC(pkt)
	if len(result) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	peerID := binary.BigEndian.Uint32(result[0][1:5])
	if peerID != 12345 {
		t.Fatalf("expected peer ID 12345 in header, got %d", peerID)
	}
}

func TestTranslateToIPSCSlotFlag(t *testing.T) {
	t.Parallel()

	// TS1 (Slot=false)
	tr := newTestTranslator(t)
	pkt := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 1)
	result := tr.TranslateToIPSC(pkt)
	if len(result) < 1 {
		t.Fatal("expected packets")
	}
	callInfo := result[0][17]
	if callInfo&0x20 != 0 {
		t.Fatalf("expected TS1 (slot bit clear), got callInfo %02X", callInfo)
	}

	// TS2 (Slot=true)
	tr2 := newTestTranslator(t)
	pkt2 := makeTestHBRPPacket(true, true, hbrpFrameTypeDataSync, 1)
	pkt2.StreamID = 0x9999
	result2 := tr2.TranslateToIPSC(pkt2)
	if len(result2) < 1 {
		t.Fatal("expected packets")
	}
	callInfo2 := result2[0][17]
	if callInfo2&0x20 == 0 {
		t.Fatalf("expected TS2 (slot bit set), got callInfo %02X", callInfo2)
	}
}

func TestTranslateToIPSCSrcDstInHeader(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	pkt := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 1)
	pkt.Src = 0x123456
	pkt.Dst = 0xABCDEF
	result := tr.TranslateToIPSC(pkt)
	if len(result) < 1 {
		t.Fatal("expected packets")
	}
	src := uint(result[0][6])<<16 | uint(result[0][7])<<8 | uint(result[0][8])
	dst := uint(result[0][9])<<16 | uint(result[0][10])<<8 | uint(result[0][11])
	if src != 0x123456 {
		t.Fatalf("expected src 0x123456, got 0x%06X", src)
	}
	if dst != 0xABCDEF {
		t.Fatalf("expected dst 0xABCDEF, got 0x%06X", dst)
	}
}

func TestTranslateToHBRPTooShort(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	result := tr.TranslateToHBRP(0x80, make([]byte, 10))
	if result != nil {
		t.Fatal("expected nil for too-short IPSC packet")
	}
}

func TestTranslateToHBRPUnsupportedType(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	result := tr.TranslateToHBRP(0x99, make([]byte, 54))
	if result != nil {
		t.Fatal("expected nil for unsupported packet type")
	}
}

func makeTestIPSCPacket(packetType byte, burstType byte, groupCall, slot bool) []byte {
	buf := make([]byte, 54)
	buf[0] = packetType

	// Peer ID
	binary.BigEndian.PutUint32(buf[1:5], 99999)

	// Src (bytes 6-8) — hardcoded test source ID
	const src uint = 100
	const dst uint = 200
	buf[6] = byte(src >> 16)
	buf[7] = byte(src >> 8)
	buf[8] = byte(src)

	// Dst (bytes 9-11)
	buf[9] = byte(dst >> 16)
	buf[10] = byte(dst >> 8)
	buf[11] = byte(dst)

	// Call type
	if groupCall {
		buf[12] = 0x02
	} else {
		buf[12] = 0x01
	}

	// Call control (bytes 13-16) - unique per call
	binary.BigEndian.PutUint32(buf[13:17], 0xAAAA)

	// Call info (byte 17)
	callInfo := byte(0x00)
	if slot {
		callInfo |= 0x20
	}
	buf[17] = callInfo

	// RTP header stub (bytes 18-29)
	buf[18] = 0x80

	// Burst type (byte 30)
	buf[30] = burstType

	return buf
}

func TestTranslateToHBRPVoiceHeader(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	data := makeTestIPSCPacket(0x80, ipscBurstVoiceHead, true, false)
	result := tr.TranslateToHBRP(0x80, data)
	if len(result) != 1 {
		t.Fatalf("expected 1 packet for voice header, got %d", len(result))
	}
	pkt := result[0]
	if pkt.Signature != "DMRD" {
		t.Fatalf("expected DMRD signature, got %q", pkt.Signature)
	}
	if pkt.FrameType != hbrpFrameTypeDataSync {
		t.Fatalf("expected frame type %d (data sync), got %d", hbrpFrameTypeDataSync, pkt.FrameType)
	}
	if pkt.Src != 100 {
		t.Fatalf("expected src 100, got %d", pkt.Src)
	}
	if pkt.Dst != 200 {
		t.Fatalf("expected dst 200, got %d", pkt.Dst)
	}
}

func TestTranslateToHBRPDuplicateHeaderSkipped(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	data := makeTestIPSCPacket(0x80, ipscBurstVoiceHead, true, false)

	// First header should produce a packet
	result := tr.TranslateToHBRP(0x80, data)
	if len(result) != 1 {
		t.Fatalf("expected 1 packet for first header, got %d", len(result))
	}

	// Second header with same call control should be skipped
	result = tr.TranslateToHBRP(0x80, data)
	if len(result) != 0 {
		t.Fatalf("expected 0 packets for duplicate header, got %d", len(result))
	}
}

func TestTranslateToHBRPVoiceTerminator(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)

	// Send header first to establish stream
	header := makeTestIPSCPacket(0x80, ipscBurstVoiceHead, true, false)
	tr.TranslateToHBRP(0x80, header)

	// Send terminator
	term := makeTestIPSCPacket(0x80, ipscBurstVoiceTerm, true, false)
	result := tr.TranslateToHBRP(0x80, term)
	if len(result) != 1 {
		t.Fatalf("expected 1 packet for terminator, got %d", len(result))
	}
	if result[0].DTypeOrVSeq != 2 { // DataTypeTerminatorWithLC = 2
		t.Fatalf("expected dtype 2 (terminator), got %d", result[0].DTypeOrVSeq)
	}
}

func TestTranslateToHBRPPrivateCall(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	data := makeTestIPSCPacket(0x81, ipscBurstVoiceHead, false, false)
	result := tr.TranslateToHBRP(0x81, data)
	if len(result) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(result))
	}
	if result[0].GroupCall {
		t.Fatal("expected GroupCall=false for private call")
	}
}

func TestTranslateToHBRPSlotTS2(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	data := makeTestIPSCPacket(0x80, ipscBurstVoiceHead, true, true)
	// Use a different call control to avoid collision
	binary.BigEndian.PutUint32(data[13:17], 0xBBBB)
	result := tr.TranslateToHBRP(0x80, data)
	if len(result) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(result))
	}
	if !result[0].Slot {
		t.Fatal("expected Slot=true for TS2")
	}
}

func TestTranslateToHBRPEndFlagCleansUp(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)

	// Send header
	header := makeTestIPSCPacket(0x80, ipscBurstVoiceHead, true, false)
	binary.BigEndian.PutUint32(header[13:17], 0xCCCC)
	tr.TranslateToHBRP(0x80, header)

	// Send another packet with end flag set (but not a terminator burst type)
	endPkt := makeTestIPSCPacket(0x80, ipscBurstVoiceHead, true, false)
	binary.BigEndian.PutUint32(endPkt[13:17], 0xCCCC)
	endPkt[17] |= 0x40 // set end flag
	tr.TranslateToHBRP(0x80, endPkt)

	// Verify the stream was cleaned up
	tr.mu.Lock()
	_, exists := tr.reverseStreams[0xCCCC]
	tr.mu.Unlock()
	if exists {
		t.Fatal("expected reverse stream to be cleaned up after end flag")
	}
}

func TestTranslateToHBRPCSBK(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	data := makeTestIPSCPacket(0x83, ipscBurstCSBK, true, false)
	binary.BigEndian.PutUint32(data[13:17], 0xDDDD)
	result := tr.TranslateToHBRP(0x83, data)
	if len(result) != 1 {
		t.Fatalf("expected 1 packet for CSBK, got %d", len(result))
	}
	if result[0].DTypeOrVSeq != 3 { // DataTypeCSBK = 3
		t.Fatalf("expected dtype 3 (CSBK), got %d", result[0].DTypeOrVSeq)
	}
}

func TestExtractFullLCBytesGroupCall(t *testing.T) {
	t.Parallel()
	pkt := hbrp.Packet{
		GroupCall: true,
		Src:       100,
		Dst:       200,
	}
	lc := extractFullLCBytes(pkt)
	// First byte should be FLCO for group call (0x00)
	if lc[0] != 0x00 {
		t.Fatalf("expected FLCO 0x00 (group), got 0x%02X", lc[0])
	}
}

func TestExtractFullLCBytesPrivateCall(t *testing.T) {
	t.Parallel()
	pkt := hbrp.Packet{
		GroupCall: false,
		Src:       100,
		Dst:       200,
	}
	lc := extractFullLCBytes(pkt)
	// First byte should be FLCO for unit-to-unit (0x03)
	if lc[0] != 0x03 {
		t.Fatalf("expected FLCO 0x03 (unit-to-unit), got 0x%02X", lc[0])
	}
}

func TestBuildIPSCHeaderDataPacket(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	pkt := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 3) // CSBK
	result := tr.TranslateToIPSC(pkt)
	if len(result) < 1 {
		t.Fatal("expected at least 1 data packet")
	}
	// Data packet should use type 0x83 (group data)
	if result[0][0] != 0x83 {
		t.Fatalf("expected data packet type 0x83, got 0x%02X", result[0][0])
	}
}

func TestBuildIPSCHeaderEndFlag(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	// First send a header
	header := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 1)
	tr.TranslateToIPSC(header)

	// Then send terminator (end flag should be set)
	term := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 2)
	term.StreamID = header.StreamID
	result := tr.TranslateToIPSC(term)
	if len(result) != 1 {
		t.Fatalf("expected 1 terminator packet, got %d", len(result))
	}
	callInfo := result[0][17]
	if callInfo&0x40 == 0 {
		t.Fatalf("expected end flag set in terminator, got callInfo %02X", callInfo)
	}
}

func TestBuildRTPHeader(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	pkt := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 1)
	result := tr.TranslateToIPSC(pkt)
	if len(result) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	// RTP version should be 2 (0x80 = version 2, no padding, no ext, 0 CSRCs)
	if result[0][18] != 0x80 {
		t.Fatalf("expected RTP version byte 0x80, got 0x%02X", result[0][18])
	}
}

func TestBuildRTPHeaderNoMarker(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)
	pkt := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 1)
	result := tr.TranslateToIPSC(pkt)
	if len(result) < 3 {
		t.Fatal("expected 3 header packets")
	}
	// Third header should not have marker bit
	pt := result[2][19]
	if pt&0x80 != 0 {
		t.Fatalf("expected no marker on third header, got PT byte 0x%02X", pt)
	}
}

func TestMultipleStreamsConcurrent(t *testing.T) {
	t.Parallel()
	tr := newTestTranslator(t)

	// Start two separate streams
	pkt1 := makeTestHBRPPacket(true, false, hbrpFrameTypeDataSync, 1)
	pkt1.StreamID = 0xAAAA
	pkt2 := makeTestHBRPPacket(true, true, hbrpFrameTypeDataSync, 1)
	pkt2.StreamID = 0xBBBB

	result1 := tr.TranslateToIPSC(pkt1)
	result2 := tr.TranslateToIPSC(pkt2)

	if len(result1) != 3 {
		t.Fatalf("stream 1: expected 3 packets, got %d", len(result1))
	}
	if len(result2) != 3 {
		t.Fatalf("stream 2: expected 3 packets, got %d", len(result2))
	}

	// Each stream should have its own call control
	cc1 := binary.BigEndian.Uint32(result1[0][13:17])
	cc2 := binary.BigEndian.Uint32(result2[0][13:17])
	if cc1 == cc2 {
		t.Fatal("expected different call control values for different streams")
	}
}

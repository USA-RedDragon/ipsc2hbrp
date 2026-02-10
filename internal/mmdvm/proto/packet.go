package proto

import (
	"fmt"
)

type Packet struct {
	Signature   string
	Seq         uint
	Src         uint
	Dst         uint
	Repeater    uint
	Slot        bool
	GroupCall   bool
	FrameType   uint
	DTypeOrVSeq uint
	StreamID    uint
	DMRData     [33]byte
}

func (p Packet) Equal(other Packet) bool {
	if p.Signature != other.Signature {
		return false
	}
	if p.Seq != other.Seq {
		return false
	}
	if p.Src != other.Src {
		return false
	}
	if p.Dst != other.Dst {
		return false
	}
	if p.Repeater != other.Repeater {
		return false
	}
	if p.Slot != other.Slot {
		return false
	}
	if p.GroupCall != other.GroupCall {
		return false
	}
	if p.FrameType != other.FrameType {
		return false
	}
	if p.DTypeOrVSeq != other.DTypeOrVSeq {
		return false
	}
	if p.StreamID != other.StreamID {
		return false
	}
	if p.DMRData != other.DMRData {
		return false
	}
	return true
}

func Decode(data []byte) (Packet, bool) {
	var packet Packet
	if len(data) < 53 {
		return packet, false
	}
	if len(data) > 55 {
		return packet, false
	}
	packet.Signature = string(data[:4])
	packet.Seq = uint(data[4])
	packet.Src = uint(data[5])<<16 | uint(data[6])<<8 | uint(data[7])
	packet.Dst = uint(data[8])<<16 | uint(data[9])<<8 | uint(data[10])
	packet.Repeater = uint(data[11])<<24 | uint(data[12])<<16 | uint(data[13])<<8 | uint(data[14])
	bits := data[15]
	packet.Slot = false
	if (bits & 0x1) != 0 { //nolint:golint,gomnd
		packet.Slot = true
	}
	packet.GroupCall = true
	if (bits & 0x2) != 0 { //nolint:golint,gomnd
		packet.GroupCall = false
	}
	packet.FrameType = uint((bits & 0xC) >> 2)    //nolint:golint,gomnd
	packet.DTypeOrVSeq = uint((bits & 0xF0) >> 4) //nolint:golint,gomnd
	packet.StreamID = uint(data[16])<<24 | uint(data[17])<<16 | uint(data[18])<<8 | uint(data[19])
	copy(packet.DMRData[:], data[20:53])
	return packet, true
}

func (p *Packet) String() string {
	return fmt.Sprintf(
		"Packet: Seq %d, Src %d, Dst %d, Repeater %d, Slot %t, GroupCall %t, FrameType=%d, StreamId %d, DMRData %v",
		p.Seq, p.Src, p.Dst, p.Repeater, p.Slot, p.GroupCall, p.FrameType, p.StreamID, p.DMRData,
	)
}

func (p *Packet) Encode() []byte {
	// Encode the packet as we decoded
	data := make([]byte, 53)
	copy(data[:4], []byte(p.Signature))
	data[4] = byte(p.Seq)
	data[5] = byte(p.Src >> 16) //nolint:golint,gomnd
	data[6] = byte(p.Src >> 8)  //nolint:golint,gomnd
	data[7] = byte(p.Src)
	data[8] = byte(p.Dst >> 16) //nolint:golint,gomnd
	data[9] = byte(p.Dst >> 8)  //nolint:golint,gomnd
	data[10] = byte(p.Dst)
	data[11] = byte(p.Repeater >> 24) //nolint:golint,gomnd
	data[12] = byte(p.Repeater >> 16) //nolint:golint,gomnd
	data[13] = byte(p.Repeater >> 8)  //nolint:golint,gomnd
	data[14] = byte(p.Repeater)
	bits := byte(0)
	if p.Slot {
		bits |= 0x1
	}
	if !p.GroupCall {
		bits |= 0x2
	}
	bits |= byte((p.FrameType & 0x3) << 2)
	bits |= byte((p.DTypeOrVSeq & 0xF) << 4)
	data[15] = bits
	data[16] = byte(p.StreamID >> 24) //nolint:golint,gomnd
	data[17] = byte(p.StreamID >> 16) //nolint:golint,gomnd
	data[18] = byte(p.StreamID >> 8)  //nolint:golint,gomnd
	data[19] = byte(p.StreamID)
	copy(data[20:53], p.DMRData[:])
	return data
}

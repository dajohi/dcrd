// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
)

// newNetAddressV2 is a convenience function for constructing a new v2 network
// address.
func newNetAddressV2(addrType NetAddressType, addrBytes []byte, port uint16) NetAddressV2 {
	timestamp := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST
	netAddr := NewNetAddressV2(addrType, addrBytes, port, timestamp,
		SFNodeNetwork)
	return *netAddr
}

var (
	ipv4IpBytes = []byte{0x7f, 0x00, 0x00, 0x01}

	ipv6IpBytes = []byte{
		0x26, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	torV3IpBytes = []byte{
		0xb8, 0x39, 0x1d, 0x20, 0x03, 0xbb, 0x3b, 0xd2,
		0x85, 0xb0, 0x35, 0xac, 0x8e, 0xb3, 0x0c, 0x80,
		0xc4, 0xe2, 0xa2, 0x9b, 0xb7, 0xa2, 0xf0, 0xce,
		0x0d, 0xf8, 0x74, 0x3c, 0x37, 0xec, 0x35, 0x93,
	}

	serializedIPv4NetAddressBytes = []byte{
		0x29, 0xab, 0x5f, 0x49, 0x00, 0x00, 0x00, 0x00, // Timestamp
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Services
		0x01, // Address type
		0x7f, 0x00, 0x00, 0x01,
		0x94, 0x23, // Port
	}

	serializedIPv6NetAddressBytes = []byte{
		0x29, 0xab, 0x5f, 0x49, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02,
		0x26, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x95, 0x23,
	}

	serializedTORv3NetAddressBytes = []byte{
		0x29, 0xab, 0x5f, 0x49, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03,
		0xb8, 0x39, 0x1d, 0x20, 0x03, 0xbb, 0x3b, 0xd2,
		0x85, 0xb0, 0x35, 0xac, 0x8e, 0xb3, 0x0c, 0x80,
		0xc4, 0xe2, 0xa2, 0x9b, 0xb7, 0xa2, 0xf0, 0xce,
		0x0d, 0xf8, 0x74, 0x3c, 0x37, 0xec, 0x35, 0x93,
		0xa4, 0x4a,
	}
)

var (
	ipv4Address  = newNetAddressV2(IPv4Address, ipv4IpBytes, 9108)
	ipv6Address  = newNetAddressV2(IPv6Address, ipv6IpBytes, 9109)
	torv3Address = newNetAddressV2(TORv3Address, torV3IpBytes, 19108)
)

// TestMaxPayloadLength verifies the maximum payload length equals the expected
// value at various protocol versions and does not exceed the maximum message
// size for any protocol message.
func TestMaxPayloadLength(t *testing.T) {
	tests := []struct {
		name string
		pver uint32
		want uint32
	}{{
		name: "protocol version 9",
		pver: AddrV2Version - 1,
		want: 0,
	}, {
		name: "protocol version 10",
		pver: AddrV2Version,
		want: 35003,
	}, {
		name: "protocol version 11",
		pver: RelayTORv3Version,
		want: 51003,
	}, {
		name: "latest protocol version",
		pver: ProtocolVersion,
		want: 51003,
	}}

	for _, test := range tests {
		// Ensure max payload is expected value for latest protocol version.
		msg := NewMsgAddrV2()
		result := msg.MaxPayloadLength(test.pver)
		if result != test.want {
			t.Errorf("%s: wrong max payload length - got %v, want %d",
				test.name, result, test.want)
		}

		// Ensure max payload length is not more than the maximum allowed for
		// any protocol message.
		if result > MaxMessagePayload {
			t.Fatalf("%s: payload length exceeds maximum message payload - "+
				"got %d, want less than %d.", test.name, result,
				MaxMessagePayload)
		}
	}
}

// TestAddrV2 tests the MsgAddrV2 API.
func TestAddrV2(t *testing.T) {
	// Ensure the command is expected value.
	wantCmd := "addrv2"
	msg := NewMsgAddrV2()
	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgAddrV2: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure NetAddresses are added properly.
	err := msg.AddAddress(ipv4Address)
	if err != nil {
		t.Errorf("AddAddress: %v", err)
	}
	if !reflect.DeepEqual(msg.AddrList[0], ipv4Address) {
		t.Errorf("AddAddress: wrong address added - got %v, want %v",
			spew.Sprint(msg.AddrList[0]), spew.Sprint(ipv4Address))
	}

	// Ensure the address list is cleared properly.
	msg.ClearAddresses()
	if len(msg.AddrList) != 0 {
		t.Errorf("ClearAddresses: address list is not empty - "+
			"got %v [%v], want %v", len(msg.AddrList),
			spew.Sprint(msg.AddrList[0]), 0)
	}

	// Ensure adding more than the max allowed addresses per message returns
	// error.
	for i := 0; i < MaxAddrPerV2Msg+1; i++ {
		err = msg.AddAddress(ipv4Address)
	}
	if err == nil {
		t.Errorf("AddAddress: expected error on too many addresses " +
			"not received")
	}

	// Make sure adding multiple addresses also returns an error when the
	// message is at max capacity.
	err = msg.AddAddresses(ipv4Address)
	if err == nil {
		t.Errorf("AddAddresses: expected error on too many addresses " +
			"not received")
	}
}

// TestAddrWire tests the MsgAddrV2 wire encode and decode for various numbers
// of addresses at the latest protocol version.
func TestAddrV2Wire(t *testing.T) {
	pver := ProtocolVersion
	tests := []struct {
		name      string
		addrs     []NetAddressV2
		wantBytes []byte
	}{{
		name: "latest protocol version with one address",
		addrs: []NetAddressV2{
			ipv4Address,
		},
		wantBytes: bytes.Join([][]byte{
			{0x01},
			serializedIPv4NetAddressBytes,
		}, []byte{}),
	}, {
		name: "latest protocol version with multiple addresses",
		addrs: []NetAddressV2{
			ipv4Address,
			ipv6Address,
			torv3Address,
		},
		wantBytes: bytes.Join([][]byte{
			{0x03},
			serializedIPv4NetAddressBytes,
			serializedIPv6NetAddressBytes,
			serializedTORv3NetAddressBytes,
		}, []byte{}),
	}}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		subject := NewMsgAddrV2()
		subject.AddAddresses(test.addrs...)

		// Encode the message to the wire format and ensure it serializes
		// correctly.
		var buf bytes.Buffer
		err := subject.BtcEncode(&buf, pver)
		if err != nil {
			t.Errorf("%q: error encoding message - %v", test.name, err)
			continue
		}
		if !reflect.DeepEqual(buf.Bytes(), test.wantBytes) {
			t.Errorf("%q: mismatched bytes -- got: %s want: %s", test.name,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.wantBytes))
			continue
		}

		// Decode the message from wire format and ensure it deserializes
		// correctly.
		var msg MsgAddrV2
		rbuf := bytes.NewReader(test.wantBytes)
		err = msg.BtcDecode(rbuf, pver)
		if err != nil {
			t.Errorf("%q: error decoding message - %v", test.name, err)
			continue
		}
		if !reflect.DeepEqual(&msg, subject) {
			t.Errorf("%q: mismatched message - got: %s want: %s", i,
				spew.Sdump(msg), spew.Sdump(subject))
			continue
		}
	}
}

// TestAddrWireErrors performs negative tests against wire encode and decode
// of MsgAddrV2 to confirm error paths work correctly.
func TestAddrV2WireErrors(t *testing.T) {
	pver := ProtocolVersion
	na := ipv4Address
	addrs := []NetAddressV2{na}
	addrv2 := NewMsgAddrV2()

	tests := []struct {
		name     string
		addrs    []NetAddressV2 // Value to encode
		bytes    []byte         // Wire encoding
		pver     uint32         // Protocol version for wire encoding
		ioLimit  int            // Max size of fixed buffer to induce errors
		writeErr error          // Expected write error
		readErr  error          // Expected read error
	}{{
		name:     "unsupported protocol version",
		pver:     AddrV2Version - 1,
		addrs:    addrs,
		bytes:    []byte{0x01},
		ioLimit:  1,
		writeErr: ErrMsgInvalidForPVer,
		readErr:  ErrMsgInvalidForPVer,
	}, {
		name:     "zero byte i/o limit",
		pver:     pver,
		addrs:    addrs,
		bytes:    []byte{0x00},
		ioLimit:  0,
		writeErr: io.ErrShortWrite,
		readErr:  io.EOF,
	}, {
		name:     "one byte i/o limit",
		pver:     pver,
		addrs:    addrs,
		bytes:    []byte{0x01},
		ioLimit:  1,
		writeErr: io.ErrShortWrite,
		readErr:  io.EOF,
	}, {
		name:     "message with no addresses",
		pver:     pver,
		addrs:    nil,
		bytes:    []byte{0x00},
		ioLimit:  1,
		writeErr: ErrTooFewAddrs,
		readErr:  ErrTooFewAddrs,
	}, {
		name: "message with too many addresses",
		pver: pver,
		addrs: func() []NetAddressV2 {
			var addrs []NetAddressV2
			for i := 0; i < MaxAddrPerV2Msg+1; i++ {
				addrs = append(addrs, na)
			}
			return addrs
		}(),
		bytes:    []byte{0xfd, 0xe9, 0x03},
		ioLimit:  3,
		writeErr: ErrTooManyAddrs,
		readErr:  ErrTooManyAddrs,
	}, {
		name:     "torv3 address invalid on protocol version 10",
		pver:     RelayTORv3Version - 1,
		addrs:    []NetAddressV2{torv3Address},
		bytes:    []byte{0x01},
		ioLimit:  int(addrv2.MaxPayloadLength(RelayTORv3Version - 1)),
		writeErr: ErrInvalidMsg,
		readErr:  ErrInvalidMsg,
	}}

	t.Logf("Running %d tests", len(tests))
	for _, test := range tests {
		subject := NewMsgAddrV2()
		subject.AddrList = test.addrs

		// Encode to wire format.
		w := newFixedWriter(test.ioLimit)
		err := subject.BtcEncode(w, test.pver)
		if !errors.Is(err, test.writeErr) {
			t.Errorf("%q: wrong error - got: %v, want: %v", test.name, err,
				test.writeErr)
			continue
		}

		// Decode from wire format.
		var msg MsgAddrV2
		r := newFixedReader(test.ioLimit, test.bytes)
		err = msg.BtcDecode(r, test.pver)
		if !errors.Is(err, test.readErr) {
			t.Errorf("%q: wrong error - got: %v, want: %v", test.name, err,
				test.readErr)
			continue
		}
	}
}
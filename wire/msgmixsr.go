// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// MsgMixSR implements the Message interface and represents a mixsr
// message.  It is used to deliver a key exchange.
// TODO - better comment
type MsgMixSR struct {
	Signature [64]byte // Signature
	Run       uint32
	DCMix     [][]byte
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixSR) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixSR.BtcDecode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := readElements(r, &msg.Signature, &msg.Run, &msg.DCMix)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixSR) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixSR.BtcEncode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := writeElements(w, msg.Signature, msg.Run, msg.DCMix)
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMixSR) Command() string {
	return CmdMixSR
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixSR) MaxPayloadLength(pver uint32) uint32 {
	return 0 // 32 + 32 + MaxTxSize + 4 + 64
}

// NewMsgMixSR returns a new mixsr message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixSR(run uint32, dcmix [][]byte) *MsgMixSR {
	return &MsgMixSR{
		Run:   run,
		DCMix: dcmix,
	}
}

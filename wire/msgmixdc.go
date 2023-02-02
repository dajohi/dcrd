// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

type MsgMixDCVector struct {
	N     int
	Msize int
	Data  []byte
}

// MsgMixDC implements the Message interface and represents a mixdc
// message.  It is used to deliver a key exchange.
// TODO - better comment
type MsgMixDC struct {
	Signature     [64]byte
	Run           uint32
	DCNet         []MsgMixDCVector
	RevealSecrets bool
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixDC) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixDC.BtcDecode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := readElements(r, &msg.Signature, &msg.Run, &msg.DCNet, &msg.RevealSecrets)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixDC) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixDC.BtcEncode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := writeElements(w, msg.Signature, msg.Run, msg.DCNet, msg.RevealSecrets)
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMixDC) Command() string {
	return CmdMixDC
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixDC) MaxPayloadLength(pver uint32) uint32 {
	return 0 // 32 + 32 + MaxTxSize + 4 + 64
}

// NewMsgMixDC returns a new mixsr message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixDC(run uint32, dcnet []MsgMixDCVector, revealSecrets bool) *MsgMixDC {
	return &MsgMixDC{
		Run:           run,
		DCNet:         dcnet,
		RevealSecrets: revealSecrets,
	}
}

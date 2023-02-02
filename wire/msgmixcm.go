// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// MsgMixCM implements the Message interface and represents a mixcm
// message.  It is used to confirm messages.
type MsgMixCM struct {
	Signature     [64]byte // Signature
	RevealSecrets bool
	Mix           []byte // BinaryRepresentable
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixCM) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixCM.BtcDecode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := readElements(r, &msg.Signature, &msg.RevealSecrets,
		&msg.Mix)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixCM) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixCM.BtcEncode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := writeElements(w, msg.Signature, msg.RevealSecrets,
		msg.Mix)
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMixCM) Command() string {
	return CmdMixCM
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixCM) MaxPayloadLength(pver uint32) uint32 {
	return 0 // 32 + 32 + MaxTxSize + 4 + 64
}

// NewMsgMixCM returns a new mixke message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixCM(mix []byte, revealSecrets bool) *MsgMixCM {
	return &MsgMixCM{
		RevealSecrets: revealSecrets,
		Mix:           mix,
	}
}

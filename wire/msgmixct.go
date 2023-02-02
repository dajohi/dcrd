// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// MsgMixCT implements the Message interface and represents a mixct
// message.  It is used to deliver a key exchange.
// TODO - better comment
type MsgMixCT struct {
	Signature   [64]byte     // Signature
	Ciphertexts [][1047]byte // Ciphertexts
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixCT) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixCT.BtcDecode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := readElements(r, &msg.Signature, &msg.Ciphertexts)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixCT) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixCT.BtcEncode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := writeElements(w, msg.Signature, msg.Ciphertexts)
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMixCT) Command() string {
	return CmdMixCT
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixCT) MaxPayloadLength(pver uint32) uint32 {
	return 0 // 32 + 32 + MaxTxSize + 4 + 64
}

// NewMsgMixCT returns a new mixct message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixCT(cipherTexts [][1047]byte) *MsgMixCT {
	return &MsgMixCT{
		Ciphertexts: cipherTexts,
	}
}

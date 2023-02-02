// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"io"
)

// MsgMixKE implements the Message interface and represents a mixke
// message.  It is used to deliver a key exchange.
type MsgMixKE struct {
	Signature  [64]byte   // Signature
	Identity   [32]byte   // PublicKey
	ECDH       [32]byte   // x25519.Public
	Commitment [32]byte   // Hash of RS (reveal secrets) message contents
	Run        uint32     // means what it means
	SeenPRs    [][32]byte // Validated signatures of PR messages
	PQPK       [1218]byte // Sntrup4591761PublicKey
}

func (msg *MsgMixKE) Data() ([]byte, error) {
	// TODO - prealloc
	w := bytes.NewBuffer(make([]byte, 20))
	err := writeElements(w, msg.ECDH, msg.Commitment, msg.Run,
		msg.SeenPRs, msg.PQPK)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixKE) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixKE.BtcDecode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := readElements(r, &msg.Signature, &msg.Identity, &msg.ECDH,
		&msg.Commitment, &msg.Run, &msg.SeenPRs, &msg.PQPK)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixKE) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixKE.BtcEncode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := writeElements(w, msg.Signature, msg.Identity, msg.ECDH,
		msg.Commitment, msg.Run, msg.SeenPRs, msg.PQPK)
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMixKE) Command() string {
	return CmdMixKE
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixKE) MaxPayloadLength(pver uint32) uint32 {
	return 0 // 32 + 32 + MaxTxSize + 4 + 64
}

// NewMsgMixKE returns a new mixke message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixKE(identity [32]byte, run uint32, seenPRs [][32]byte,
	ecdh [32]byte, pqpk [1218]byte, commitment [32]byte) *MsgMixKE {

	return &MsgMixKE{
		Identity:   identity,
		Run:        run,
		SeenPRs:    seenPRs,
		ECDH:       ecdh,
		PQPK:       pqpk,
		Commitment: commitment,
	}
}

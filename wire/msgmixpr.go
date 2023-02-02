// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"io"
)

// MsgMixPR implements the Message interface and represents a mixpr
// message.  It is used to deliver pair request for a given utxo.
type MsgMixPR struct {
	Signature    [64]byte // Signature
	Identity     [32]byte // PublicKey
	Amount       int64
	ScriptClass  string
	TxVersion    uint16
	LockTime     uint32
	Expiry       uint32
	MessageCount uint32     // Number of messages being mixed
	UTXOs        []OutPoint // Unmixed transaction inputs and change output.
	Change       TxOut
}

func (msg *MsgMixPR) Data() ([]byte, error) {
	// TODO - prealloc
	w := bytes.NewBuffer(make([]byte, 20))
	err := writeElements(w, msg.Amount, msg.ScriptClass, msg.TxVersion,
		msg.LockTime, msg.Expiry, msg.MessageCount, msg.UTXOs, msg.Change)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixPR) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixPR.BtcDecode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := readElements(r, &msg.Signature, &msg.Identity, &msg.Amount,
		&msg.ScriptClass, &msg.TxVersion, msg.LockTime, msg.Expiry,
		msg.MessageCount, &msg.UTXOs, &msg.Change)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixPR) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixPR.BtcEncode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := writeElements(w, msg.Signature, msg.Identity, msg.Amount,
		msg.ScriptClass, msg.TxVersion, msg.LockTime, msg.Expiry,
		msg.MessageCount, msg.UTXOs, msg.Change)
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMixPR) Command() string {
	return CmdMixPR
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixPR) MaxPayloadLength(pver uint32) uint32 {
	return 0 // TODO - 64 + 32 + 8 + 2 + 2 + 2 + 4 + 4 + MaxTxSize
}

// NewMsgMixPR returns a new mixpr message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixPR(identity [32]byte, amount int64,
	scriptClass string, txVersion uint16, lockTime, expiry,
	messageCount uint32, utxos []OutPoint, change TxOut) *MsgMixPR {
	return &MsgMixPR{
		Identity:     identity,
		Amount:       amount,
		ScriptClass:  scriptClass,
		TxVersion:    txVersion,
		LockTime:     lockTime,
		Expiry:       expiry,
		MessageCount: messageCount,
		UTXOs:        utxos,
		Change:       change,
	}
}

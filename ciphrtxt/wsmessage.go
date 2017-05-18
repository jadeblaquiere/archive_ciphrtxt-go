// Copyright (c) 2016, Joseph deBlaquiere <jadeblaquiere@yahoo.com>
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of ciphrtxt nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package ciphrtxt

import (
	"bytes"
	"encoding/binary"
	//"encoding/hex"
	"encoding/json"
	"errors"
	//"fmt"
	"hash/crc32"
	//"io"
	//"io/ioutil"
	//"net/http"
	//"os"
	//"strconv"
	//"sync"
	"time"
	//"github.com/gorilla/websocket"
)

const (
	WSDefaultMessageVersion = 0x0001

	WSRequestTypeTime         = 0x0001
	WSRequestTypeHeadersSince = 0x0002
	WSRequestTypeStatus       = 0x0003

	WSResponseTypeTime   = 0x0101
	WSResponseTypeHeader = 0x0102
	WSResponseTypeStatus = 0x0103
)

// WSMessage implements the ciphrtxt websocket wire protocol. All requests
// and responses are encoded/decoded via this package.
type WSMessage struct {
	Ver     uint16
	Type    uint16
	DataLen uint64
	cksum   uint32
	Data    []byte
}

func DeserializeWSMessage(raw []byte) (wsm *WSMessage, err error) {
	slen := len(raw)
	if slen < 16 {
		return nil, errors.New("DeserializeWSMessage: message too short")
	}
	csum := binary.BigEndian.Uint32(raw[slen-4:])
	if crc32.ChecksumIEEE(raw[:slen-4]) != csum {
		return nil, errors.New("DeserializeWSMessage: checksum failed")
	}
	msg := new(WSMessage)
	msg.Ver = binary.BigEndian.Uint16(raw[0:2])
	msg.Type = binary.BigEndian.Uint16(raw[2:4])
	msg.DataLen = binary.BigEndian.Uint64(raw[4:12])
	if uint64(slen) != msg.DataLen+16 {
		return nil, errors.New("DeserializeWSMessage: length mismatch")
	}
	if msg.DataLen > 0 {
		msg.Data = make([]byte, msg.DataLen)
		copy(msg.Data[:], raw[12:slen-4])
	}
	return msg, nil
}

func (wsm *WSMessage) SerializeMessage() (msgbytes []byte) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, wsm.Ver)
	binary.Write(buf, binary.BigEndian, wsm.Type)
	wsm.DataLen = uint64(len(wsm.Data))
	binary.Write(buf, binary.BigEndian, wsm.DataLen)
	buf.Write(wsm.Data)
	bbytes := buf.Bytes()
	wsm.cksum = crc32.ChecksumIEEE(bbytes)
	binary.Write(buf, binary.BigEndian, wsm.cksum)
	bmsg := make([]byte, buf.Len())
	copy(bmsg[:], buf.Bytes()[:])
	return bmsg
}

func NewWSMessageTimeRequest() (wsm *WSMessage) {
	wsm = new(WSMessage)
	wsm.Ver = 0x0001
	wsm.Type = WSRequestTypeTime
	wsm.DataLen = 0
	wsm.Data = make([]byte, 0)
	return wsm
}

func NewWSMessageStatusRequest() (wsm *WSMessage) {
	wsm = new(WSMessage)
	wsm.Ver = 0x0001
	wsm.Type = WSRequestTypeStatus
	wsm.DataLen = 0
	wsm.Data = make([]byte, 0)
	return wsm
}

func NewWSMessageHeadersSinceRequest(unixtime uint32) (wsm *WSMessage) {
	wsm = new(WSMessage)
	wsm.Ver = 0x0001
	wsm.Type = WSRequestTypeHeadersSince
	wsm.DataLen = 4
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, unixtime)
	wsm.Data = make([]byte, 4)
	copy(wsm.Data[:], buf.Bytes()[:])
	return wsm
}

func NewWSMessageTimeResponse() (wsm *WSMessage) {
	unixtime := uint32(time.Now().Unix())
	wsm = new(WSMessage)
	wsm.Ver = 0x0001
	wsm.Type = WSResponseTypeStatus
	wsm.DataLen = 4
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, unixtime)
	wsm.Data = make([]byte, 0)
	return wsm
}

func NewWSMessageHeaderReponse(hdr *RawMessageHeader) (wsm *WSMessage) {
	hdrBody := hdr.Serialize()
	wsm = new(WSMessage)
	wsm.Ver = 0x0001
	wsm.Type = WSResponseTypeHeader
	wsm.DataLen = uint64(len(hdrBody))
	wsm.Data = make([]byte, wsm.DataLen)
	copy(wsm.Data[:], hdrBody[:])
	return wsm
}

func NewWSMessageStatusResponse(sr *StatusResponse) (wsm *WSMessage) {
	statusJSON, err := json.Marshal(sr)
	if err != nil {
		return nil
	}
	wsm = new(WSMessage)
	wsm.Ver = 0x0001
	wsm.Type = WSResponseTypeStatus
	wsm.DataLen = uint64(len(statusJSON))
	wsm.Data = make([]byte, wsm.DataLen)
	copy(wsm.Data[:], statusJSON[:])
	return wsm
}

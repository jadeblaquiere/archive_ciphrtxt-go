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
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	//"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

type MessageHeader interface {
	Serialize() string
	Deserialize(string) error
	MessageTime() time.Time
	ExpireTime() time.Time
	IKey() []byte
	Hash() []byte
	dbKeys(uint32) (*dbkeys, error)
}

const MessageHeaderLengthV1 = 5 + 1 + // "M0100" + ":"
	8 + 1 + // time(32 bit hex) + ":"
	8 + 1 + // expire(32 bit hex) + ":"
	66 + 1 + // I (256-bit point, compressed hex) + ":"
	66 + 1 + // I (256-bit point, compressed hex) + ":"
	66 + 1 + // I (256-bit point, compressed hex) + ":"
	64 + 1 + // r (256-bit integer, hex) + ":"
	64 // s (256-bit integer, hex)

type SerializedMessageHeaderV1 [MessageHeaderLengthV1]byte

// V2 message header format:
// "M\0x02\0x00\0x00" =>  4 bytes => Message File, v 2.00 / 0200
// Message Time       =>  4 bytes => 32-bit unsigned UNIX time
// Message Expire     =>  4 bytes => 32-bit unsigned UNIX time
// I (point)          => 33 bytes => 256-bit ECC point, compressed
// J (point)          => 33 bytes => 256-bit ECC point, compressed
// K (point)          => 33 bytes => 256-bit ECC point, compressed
// blocklength        =>  4 bytes => 32 bit block length
// reserved           =>  8 bytes => 64 bits reserved (should be zero)
// short (subtotal)   =============> 123 bytes (164 bytes in base64 encoding)
// r, s               => 64 bytes => 2*256-bit ECDSA signature
// nonce              =>  5 bytes => 40-bit Nonce
// sig + nonce        =============> 69 bytes (92 bytes in base64 encoding)
//                      192 bytes (256 bytes in base64)
// the encrypted message is signed along with the short header and then the
// nonce is calculated to ensure the hash of the long header has nbits zeros
// (see also Authenticated Encryption with Additional Data, AEAD, and Hashcash)

//const ShortMessageHeaderLengthV2 = (4+4+4+33+33+33+4+8)
const ShortMessageHeaderLengthV2 = (123)

//const ShortMessageHeaderLengthB64V2 = ((ShortMessageHeaderLengthV2 * 4) / 3)
const ShortMessageHeaderLengthB64V2 = (164)

//const MessageHeaderLengthV2 = (ShortMessageHeaderLengthV2+32+32+5)
const MessageHeaderLengthV2 = (192)

//const MessageHeaderLengthB64V2 = ((MessageHeaderLengthV2 * 4) / 3)
const MessageHeaderLengthB64V2 = (256)

type SerializedMessageHeaderV2 [MessageHeaderLengthB64V2]byte
type BinaryMessageHeaderV2 [MessageHeaderLengthV2]byte

// RawMessageHeader treats larger data objects (EC Points, big integers) as strings
// instead of parsing them to their numerical value

type MessageHeaderJSON struct {
	Version   string `json:"version"`
	Time      uint32 `json:"time"`
	Expire    uint32 `json:"expire"`
	TimeStr   string `json:"time_str"`
	ExpireStr string `json:"expire_str"`
	I         string `json:"I"`
	J         string `json:"J"`
	K         string `json:"K"`
	Size      uint64 `json:"Size"`
	R         string `json:"sig_r"`
	S         string `json:"sig_s"`
	Nonce     uint64 `json:"nonce"`
}

type RawMessageHeader struct {
	version  string
	time     uint32
	expire   uint32
	I        []byte
	J        []byte
	K        []byte
	blocklen uint32
	reserved uint64
	r        []byte
	s        []byte
	nonce    uint64
}

type RawMessageHeaderSlice []RawMessageHeader

func (z *RawMessageHeader) deserializeV1(s string) error {
	var err error
	var t64 uint64
	var d = strings.Split(s, ":")
	if len(d) != 8 || strings.Compare(d[0], "M0100") != 0 {
		return errors.New("V1 version string error")
	}
	z.version = "0100"
	t64, _ = strconv.ParseUint(d[1], 16, 32)
	z.time = uint32(t64)
	t64, _ = strconv.ParseUint(d[2], 16, 32)
	z.expire = uint32(t64)
	z.I, err = hex.DecodeString(d[3])
	if err != nil {
		return errors.New("V1 Error decoding I value as hex")
	}
	z.J, err = hex.DecodeString(d[4])
	if err != nil {
		return errors.New("V1 Error decoding J value as hex")
	}
	z.K, err = hex.DecodeString(d[5])
	if err != nil {
		return errors.New("V1 Error decoding K value as hex")
	}
	z.r, err = hex.DecodeString(d[6])
	if err != nil {
		return errors.New("V1 Error decoding r value as hex")
	}
	z.s, err = hex.DecodeString(d[7])
	if err != nil {
		return errors.New("V1 Error decoding s value as hex")
	}
	return nil
}

func (z *RawMessageHeader) deserializeV2(s string) error {
	var err error
	smh := make([]byte, 0)
	if len(s) < ShortMessageHeaderLengthB64V2 {
		//fmt.Println("message too short")
		return errors.New("V2 Header too short")
	}
	if len(s) >= MessageHeaderLengthB64V2 {
		smh, err = base64.StdEncoding.DecodeString(s[:MessageHeaderLengthB64V2])
	} else {
		smh, err = base64.StdEncoding.DecodeString(s[:ShortMessageHeaderLengthB64V2])
	}
	if err != nil {
		//fmt.Println("base64 conversion failed")
		return errors.New("V2 not in base64")
	}
	return z.importBinaryHeaderV2(smh[:])
}

func (z *RawMessageHeader) importBinaryHeaderV2(smh []byte) error {
	if len(smh) < ShortMessageHeaderLengthV2 {
		return errors.New("V2 Header too short")
	}
	if bytes.Compare(smh[:4], []byte("M\x02\x00\x00")) != 0 {
		//fmt.Println("v0200 version string mismatch")
		return errors.New("V2 version string mismatch")
	}
	z.version = "0200"
	z.time = binary.BigEndian.Uint32(smh[4:8])
	z.expire = binary.BigEndian.Uint32(smh[8:12])
	//z.I = string(smh[12:45])
	//z.J = string(smh[45:78])
	//z.K = string(smh[78:111])
	z.I = make([]byte, 33)
	copy(z.I, smh[12:45])
	z.J = make([]byte, 33)
	copy(z.J, smh[45:78])
	z.K = make([]byte, 33)
	copy(z.K, smh[78:111])
	z.blocklen = binary.BigEndian.Uint32(smh[111:115])
	z.reserved = binary.BigEndian.Uint64(smh[115:123])
	if len(smh) >= MessageHeaderLengthV2 {
		var ui8 uint8
		var ui32 uint32
		z.r = make([]byte, 32)
		copy(z.r, smh[123:155])
		z.s = make([]byte, 32)
		copy(z.s, smh[155:187])
		bufnonce := bytes.NewBuffer(smh[187:188])
		binary.Read(bufnonce, binary.BigEndian, &ui8)
		bufnonce = bytes.NewBuffer(smh[188:192])
		binary.Read(bufnonce, binary.BigEndian, &ui32)
		z.nonce = ((uint64)(ui8) << 32)
		z.nonce += (uint64)(ui32)
	}
	//jsontxt, _ := json.Marshal(z.JSON())
	//fmt.Printf("imported as (JSON) %s\n", jsontxt)
	return nil
}

func (z *RawMessageHeader) Deserialize(s string) error {
	if strings.Compare(s[:3], "M01") == 0 {
		return z.deserializeV1(s)
	} else {
		return z.deserializeV2(s)
	}
}

func (z *RawMessageHeader) serializeV1() *SerializedMessageHeaderV1 {
	smh := new(SerializedMessageHeaderV1)
	I := hex.EncodeToString(z.I)
	J := hex.EncodeToString(z.J)
	K := hex.EncodeToString(z.K)
	r := hex.EncodeToString(z.r)
	s := hex.EncodeToString(z.s)
	ss := fmt.Sprintf("M%s:%08X:%08X:%s:%s:%s:%s:%s", z.version, z.time, z.expire, I, J, K, r, s)
	//fmt.Println("serialized as : " + ss)
	if len(ss) != MessageHeaderLengthV1 {
		//fmt.Printf("Message length invalid: %d chars\n", len(ss))
		return nil
	}
	copy(smh[:], ss)
	return smh
}

func (z *RawMessageHeader) exportBinaryHeaderV2() *BinaryMessageHeaderV2 {
	buf := new(bytes.Buffer)
	buf.WriteString("M\x02\x00\x00")
	binary.Write(buf, binary.BigEndian, z.time)
	binary.Write(buf, binary.BigEndian, z.expire)
	buf.Write(z.I)
	buf.Write(z.J)
	buf.Write(z.K)
	binary.Write(buf, binary.BigEndian, z.blocklen)
	binary.Write(buf, binary.BigEndian, z.reserved)
	buf.Write(z.r)
	buf.Write(z.s)
	binary.Write(buf, binary.BigEndian, uint8(z.nonce>>32))
	binary.Write(buf, binary.BigEndian, uint32(z.nonce&0xFFFFFFFF))
	//fmt.Println("serialized as : " + hex.EncodeToString(buf.Bytes()))
	if buf.Len() != MessageHeaderLengthV2 {
		//fmt.Printf("Message length invalid: %d chars\n", buf.Len())
		return nil
	}
	bmh := new(BinaryMessageHeaderV2)
	copy(bmh[:], buf.Bytes()[:])
	return bmh
}

func (z *RawMessageHeader) serializeV2() *SerializedMessageHeaderV2 {
	bmh := z.exportBinaryHeaderV2()
	b64 := make([]byte, MessageHeaderLengthB64V2)
	base64.StdEncoding.Encode(b64, bmh[:])
	//fmt.Println("as b64 " + string(b64))
	smh := new(SerializedMessageHeaderV2)
	copy(smh[:], b64)
	return smh
}

func (z *RawMessageHeader) Serialize() string {
	if strings.Compare(z.version, "0100") == 0 {
		return string(z.serializeV1()[:])
	} else {
		return string(z.serializeV2()[:])
	}
}

func (z *RawMessageHeader) SerializeV1() *SerializedMessageHeaderV1 {
	if strings.Compare(z.version, "0100") == 0 {
		return z.serializeV1()
	} else {
		return nil
	}
}

func (z *RawMessageHeader) SerializeV2() *SerializedMessageHeaderV2 {
	if strings.Compare(z.version, "0100") == 0 {
		return nil
	} else {
		return z.serializeV2()
	}
}

func (z *RawMessageHeader) ExportBinaryHeaderV2() *BinaryMessageHeaderV2 {
	if strings.Compare(z.version, "0100") == 0 {
		return nil
	} else {
		return z.exportBinaryHeaderV2()
	}
}

func ImportBinaryHeaderV2(smh []byte) *RawMessageHeader {
	z := new(RawMessageHeader)
	if z.importBinaryHeaderV2(smh) != nil {
		return nil
	}
	return z
}

func (z *RawMessageHeader) MessageTime() time.Time {
	return time.Unix(int64(z.time), 0)
}

func (z *RawMessageHeader) ExpireTime() time.Time {
	return time.Unix(int64(z.expire), 0)
}

func (z *RawMessageHeader) IKey() (k []byte) {
	return z.I
}

func (z *RawMessageHeader) Hash() []byte {
	hashval := sha256.Sum256([]byte(z.Serialize()))
	return hashval[:]
}

// Len, Less, Swap used for sorting slices of RMH

func (z RawMessageHeaderSlice) Len() int {
	return len(z)
}

func (z RawMessageHeaderSlice) Less(i, j int) bool {
	if z[i].time < z[j].time {
		return true
	}
	if z[i].time > z[j].time {
		return false
	}
	for x := 0; x < 33; x++ {
		if z[i].I[x] < z[j].I[x] {
			return true
		}
		if z[i].I[x] > z[j].I[x] {
			return false
		}
	}
	return false
}

func (z RawMessageHeaderSlice) Swap(i, j int) {
	t1 := z[i].Serialize()
	t2 := z[j].Serialize()
	z[j].Deserialize(t1)
	z[i].Deserialize(t2)
}

func (z *RawMessageHeader) JSON() *MessageHeaderJSON {
	r := new(MessageHeaderJSON)
	r.Version = z.version
	r.Time = z.time
	r.Expire = z.expire
	r.TimeStr = time.Unix(int64(z.time), 0).UTC().Format("2006-01-02 15:04:05")
	r.ExpireStr = time.Unix(int64(z.expire), 0).UTC().Format("2006-01-02 15:04:05")
	r.I = hex.EncodeToString(z.I)
	r.J = hex.EncodeToString(z.J)
	r.K = hex.EncodeToString(z.K)
	r.Size = uint64(z.blocklen+1) * MessageHeaderLengthB64V2
	r.R = hex.EncodeToString(z.r)
	r.S = hex.EncodeToString(z.s)
	r.Nonce = z.nonce

	return r
}

func (h *RawMessageHeader) dbKeys(servertime uint32) (dbk *dbkeys, err error) {
	dbk = new(dbkeys)
	dbk.date, err = hex.DecodeString(fmt.Sprintf("D0%08X", h.time))
	if err != nil {
		return nil, err
	}
	dbk.date = append(dbk.date, h.I...)
	dbk.servertime, err = hex.DecodeString(fmt.Sprintf("C0%08X", servertime))
	if err != nil {
		return nil, err
	}
	dbk.servertime = append(dbk.servertime, h.I...)
	dbk.expire, err = hex.DecodeString(fmt.Sprintf("E0%08X", h.expire))
	if err != nil {
		return nil, err
	}
	dbk.expire = append(dbk.expire, h.I...)
	dbk.I = h.I
	return dbk, err
}

type FullMessageHeader struct {
	rmh RawMessageHeader
	I   big.Int
	J   big.Int
	K   big.Int
	r   big.Int
	s   big.Int
}

func padbytes(x *big.Int, nbyte int) []byte {
	if x.Sign() < 0 {
		return nil
	}
	lsbytes := x.Bytes()
	lenls := len(lsbytes)
	if lenls > nbyte {
		return nil
	} else if lenls == nbyte {
		return lsbytes
	}
	pad := make([]byte, nbyte)
	copy(pad[(nbyte-lenls):], lsbytes[:])
	return pad
}

func (z *FullMessageHeader) Serialize() string {
	z.rmh.I = padbytes(&z.I, 33)
	z.rmh.J = padbytes(&z.J, 33)
	z.rmh.K = padbytes(&z.K, 33)
	z.rmh.r = padbytes(&z.r, 32)
	z.rmh.s = padbytes(&z.s, 32)
	return z.rmh.Serialize()
}

func (z *FullMessageHeader) Deserialize(s string) error {
	err := z.rmh.Deserialize(s)
	if err != nil {
		return err
	}
	z.I.SetBytes(z.rmh.I)
	z.J.SetBytes(z.rmh.J)
	z.K.SetBytes(z.rmh.K)
	z.r.SetBytes(z.rmh.r)
	z.s.SetBytes(z.rmh.s)
	return nil
}

func (z *FullMessageHeader) MessageTime() time.Time {
	return z.rmh.MessageTime()
}

func (z *FullMessageHeader) ExpireTime() time.Time {
	return z.rmh.ExpireTime()
}

func (z *FullMessageHeader) IKey() []byte {
	return padbytes(&z.I, 33)
}

func (z *FullMessageHeader) Hash() []byte {
	hashval := sha256.Sum256([]byte(z.Serialize()))
	return hashval[:]
}

func (z *FullMessageHeader) dbKeys(servertime uint32) (dbk *dbkeys, err error) {
	z.rmh.I = padbytes(&z.I, 33)
	return z.rmh.dbKeys(servertime)
}

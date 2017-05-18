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
	//"encoding/base64"
	//"encoding/hex"
	"encoding/binary"
	//"fmt"
	//"io/ioutil"
	"os"
	//"strconv"
	//"strings"
	"time"
)

type MessageFile struct {
	RawMessageHeader
	Size       uint64
	Servertime uint32
	Filepath   string
}

type MessageFileSlice []MessageFile

func Ingest(filepath string) *MessageFile {
	f, err := os.Open(filepath)
	if err != nil {
		return nil
	}
	defer f.Close()

	finfo, err := f.Stat()
	if err != nil {
		return nil
	}

	// read header
	smh := make([]byte, MessageHeaderLengthB64V2)
	hlen, err := f.Read(smh)
	if err != nil {
		return nil
	}
	if hlen != MessageHeaderLengthB64V2 {
		return nil
	}

	z := new(MessageFile)

	// parse message header
	if z.RawMessageHeader.Deserialize(string(smh)) == nil {
		return nil
	}

	// validate header hash
	hh := z.RawMessageHeader.Hash()
	if (hh[0] != 0) || (hh[1] != 0) {
		return nil
	}

	// check that file size is = blocklen + 1 blocks
	if (int64(z.blocklen+1) * MessageHeaderLengthB64V2) != finfo.Size() {
		return nil
	}

	z.Filepath = filepath
	z.Size = uint64(finfo.Size())
	z.Servertime = uint32(time.Now().Unix())

	return z
}

func (z *MessageFile) Move(filepath string) error {
	err := os.Rename(z.Filepath, filepath)
	if err != nil {
		return err
	}
	z.Filepath = filepath
	return nil
}

func (z *MessageFile) Serialize() []byte {
	buf := new(bytes.Buffer)
	header := z.RawMessageHeader.ExportBinaryHeaderV2()
	buf.Write(header[:])
	binary.Write(buf, binary.BigEndian, z.Size)
	binary.Write(buf, binary.BigEndian, z.Servertime)
	binary.Write(buf, binary.BigEndian, int32(len(z.Filepath)))
	buf.WriteString(z.Filepath)
	bmh := make([]byte, buf.Len())
	copy(bmh[:], buf.Bytes()[:])
	return bmh
}

func (z *MessageFile) Deserialize(bmh []byte) *MessageFile {
	if len(bmh) < (MessageHeaderLengthV2 + 16) {
		return nil
	}
	if z.RawMessageHeader.importBinaryHeaderV2(bmh) == nil {
		return nil
	}
	z.Size = binary.BigEndian.Uint64(bmh[MessageHeaderLengthV2 : MessageHeaderLengthV2+8])
	z.Servertime = binary.BigEndian.Uint32(bmh[MessageHeaderLengthV2+8 : MessageHeaderLengthV2+12])
	lenfilepath := binary.BigEndian.Uint32(bmh[MessageHeaderLengthV2+12 : MessageHeaderLengthV2+16])
	if len(bmh) < (MessageHeaderLengthV2 + 16 + int(lenfilepath)) {
		return nil
	}
	fpath := make([]byte, lenfilepath)
	copy(fpath[:], bmh[MessageHeaderLengthV2+16:MessageHeaderLengthV2+16+lenfilepath])
	z.Filepath = string(fpath)
	return z
}

// Len, Less, Swap used for sorting slices of RMH

func (z MessageFileSlice) Len() int {
	return len(z)
}

func (z MessageFileSlice) Less(i, j int) bool {
	if z[i].RawMessageHeader.time < z[j].RawMessageHeader.time {
		return true
	}
	if z[i].RawMessageHeader.time > z[j].RawMessageHeader.time {
		return false
	}
	for x := 0; x < 33; x++ {
		if z[i].RawMessageHeader.I[x] < z[j].RawMessageHeader.I[x] {
			return true
		}
		if z[i].RawMessageHeader.I[x] > z[j].RawMessageHeader.I[x] {
			return false
		}
	}
	return false
}

func (z MessageFileSlice) Swap(i, j int) {
	t1 := z[i].Serialize()
	t2 := z[j].Serialize()
	z[j].Deserialize(t1)
	z[i].Deserialize(t2)
}

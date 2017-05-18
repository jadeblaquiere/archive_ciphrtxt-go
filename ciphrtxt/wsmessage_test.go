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
	"testing"

	"bytes"
	//"math/big"
	//"math/rand"
	//"net/http"
	//"io"
	//"io/ioutil"
	//"encoding/base64"
	//"encoding/hex"
	//"encoding/json"
	"fmt"
	//"math/rand"
	//"os"
	//"strconv"
	//"strings"
	//"sync"
	"time"
)

func TestWSMSerializeDeserialize(t *testing.T) {
	trq := NewWSMessageTimeRequest()
	trqSer := trq.SerializeMessage()
	if trqSer == nil {
		fmt.Println("Error serializing TimeRequest")
		t.Fail()
	}
	fmt.Printf("Time Request serialized message:")
	for i := 0; i < len(trqSer); i++ {
		fmt.Printf("%02X", trqSer[i])
	}
	fmt.Println("")
	trqDes, err := DeserializeWSMessage(trqSer)
	if err != nil {
		fmt.Println("Deserialization failed:", err)
		t.Fail()
	}
	if (trqDes.Ver != trq.Ver) || (trqDes.Type != trq.Type) || (trqDes.DataLen != trq.DataLen) || (bytes.Compare(trq.Data, trqDes.Data) != 0) {
		fmt.Println("Deserialized data mismatch")
		t.Fail()
	}

	srq := NewWSMessageStatusRequest()
	srqSer := srq.SerializeMessage()
	if srqSer == nil {
		fmt.Println("Error serializing StatusRequest")
		t.Fail()
	}
	fmt.Printf("Status Request serialized message:")
	for i := 0; i < len(srqSer); i++ {
		fmt.Printf("%02X", srqSer[i])
	}
	fmt.Println("")
	srqDes, err := DeserializeWSMessage(srqSer)
	if err != nil {
		fmt.Println("Deserialization failed:", err)
		t.Fail()
	}
	if (srqDes.Ver != srq.Ver) || (srqDes.Type != srq.Type) || (srqDes.DataLen != srq.DataLen) || (bytes.Compare(srq.Data, srqDes.Data) != 0) {
		fmt.Println("Deserialized data mismatch")
		t.Fail()
	}

	tMinus5Min := uint32(time.Now().Unix())
	hsrq := NewWSMessageHeadersSinceRequest(tMinus5Min)
	hsrqSer := hsrq.SerializeMessage()
	if hsrqSer == nil {
		fmt.Println("Error serializing StatusRequest")
		t.Fail()
	}
	fmt.Printf("Headers Since Request serialized message:")
	for i := 0; i < len(hsrqSer); i++ {
		fmt.Printf("%02X", hsrqSer[i])
	}
	fmt.Println("")
	hsrqDes, err := DeserializeWSMessage(hsrqSer)
	if err != nil {
		fmt.Println("Deserialization failed:", err)
		t.Fail()
	}
	if (hsrqDes.Ver != hsrq.Ver) || (hsrqDes.Type != hsrq.Type) || (hsrqDes.DataLen != hsrq.DataLen) || (bytes.Compare(hsrq.Data, hsrqDes.Data) != 0) {
		fmt.Println("Deserialized data mismatch")
		t.Fail()
	}
}

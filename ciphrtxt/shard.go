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

// ShardSector defines a sector of coverage from the message space by representing
// that message space as a circle with 512 potential buckets based on the sign
// bit and the 8 most-significant bits of the I point value in compressed form. 
// Start values span from 0x200 to 0x3FF. The number of buckets stored is 
// 512 >> ring where ring is a value in (0 .. 9). Ring 0 would capture the
// full 512 bins and ring 9 stores would only capture 1 bin. 

package ciphrtxt

import (
    //"net/http"
    //"io"
    //"io/ioutil"
    "encoding/binary"
    //"encoding/hex"
    //"encoding/json"
    //"fmt"
    //"errors"
    //"github.com/syndtr/goleveldb/leveldb"
    //"github.com/syndtr/goleveldb/leveldb/util"
    //"math/rand"
    //"os"
    //"strconv"
    //"sync"
    //"time"
)

const ShardSectorOuterRing = 9
const ShardBaseVal = 0x0200

// derived values

const ShardNBins = (1 << ShardSectorOuterRing)
const ShardMaxVal = (ShardBaseVal + ShardNBins)

type ShardSector struct {
    Start   int  `json:"start"`
    Ring    uint `json:"ring"`
}

func (s *ShardSector) Contains(I []byte) (c bool) {
    ringsz := ShardNBins >> s.Ring
    end := s.Start + ringsz
    
    i := int(binary.BigEndian.Uint16(I[:2]))
    if end > ShardMaxVal {
        if (i < s.Start) && (i >= (end - ShardNBins)) {
            return false
        }
    } else {
        if (i < s.Start) || (i >= end) {
            return false
        }
    }
    return true
}


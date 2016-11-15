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
    //"math/big"
    //"math/rand"
    "net/http"
    "io"
    //"io/ioutil"
    //"encoding/base64"
    "encoding/hex"
    //"encoding/json"
    "fmt"
    "math/rand"
    "os"
    "strconv"
    //"sync"
    "time"
)

func TestMessageIngestMove (t *testing.T) {
    hc, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc.Close()

    // validate based on messages from the last hour
    now := time.Now().Unix()
    mh, err := hc.getHeadersSince(uint32(now-3600))
    if err != nil {
        fmt.Println("error getHeaderSince - test failed")
        t.Fail()
    }
    
    if len(mh) == 0 {
        fmt.Println("no message headers received - test failed")
        t.Fail()
    }
    
    for _, h := range mh {
        I := h.IKey()
        res, err := http.Get("http://violet.ciphrtxt.com:7754/api/message/download/" + hex.EncodeToString(I))
        if err != nil {
            fmt.Println("whoops:", err)
            t.Fail()
        }
        tmptime := time.Now().UnixNano()
        filepath := "./receive/"+ strconv.Itoa(int(tmptime))
        fmt.Printf("receiving %s as %s\n",hex.EncodeToString(I), filepath)
        f, err := os.Create(filepath)
        if err != nil {
            fmt.Println("whoops:", err)
            t.Fail()
        } else {
            io.Copy(f, res.Body)
            f.Close()
            m := Ingest(filepath)
            if m == nil {
                fmt.Println("whoops:", err)
                t.Fail()
            } else {
                Ihex := hex.EncodeToString(m.IKey())
                filemove := "./messages/store/" + Ihex[:4] + "/" + Ihex 
                //fmt.Printf("moving to %s\n", filemove)
                err = m.Move(filemove)
                if err != nil {
                    fmt.Println("whoops:", err)
                    t.Fail()
                }
                mse := m.Serialize()
                //fmt.Printf("Encoded as %s\n", hex.EncodeToString(mse))
                mde := new(MessageFile).Deserialize(mse)
                if mde.Size != m.Size {
                    fmt.Println("Deserialize(Serialize()) size mismatch")
                    t.Fail()
                }
                if mde.Servertime != m.Servertime {
                    fmt.Println("Deserialize(Serialize()) servertime mismatch")
                    t.Fail()
                }
                if mde.Filepath != m.Filepath {
                    fmt.Println("Deserialize(Serialize()) filepath mismatch")
                    t.Fail()
                }
                //fmt.Printf("File path is %s\n", m.Filepath)
            }
        }
    }
}

func TestOpenMessageStore (t *testing.T) {
    lhc, err := OpenLocalHeaderCache("headers")
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    defer lhc.Close()
    
    rand.Seed(time.Now().Unix())
    startbin := rand.Intn(0x200) + 0x200

    ms, err := OpenMessageStore("./messages", lhc, startbin)
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    defer ms.Close()
    
    ms.pruneExpired()
    
    lhc.AddPeer("indigo.ciphrtxt.com",7754)
    lhc.AddPeer("violet.ciphrtxt.com",7754)
    
    lhc.Sync()
    
    target := ShardSector{
        Start: startbin,
        Ring: 0,
    }
    
    ms.SetTarget(target)
    
    for i := 60 ; i > 0 ; i-- {
        fmt.Printf("\rsleeping %d seconds  ", i)
        time.Sleep(time.Second * 1)
    }
    fmt.Println(" ... done")
    
    ms.Sync()
}


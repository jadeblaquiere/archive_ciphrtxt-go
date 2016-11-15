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
    "math/rand"
    "net/http"
    "io/ioutil"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "sort"
    "strconv"
    "sync"
    "time"
)

type THeaderListResponse struct {
    HeaderList []string `json:"header_list"`
}

func TestDeserializeSerialize (t *testing.T) {
    res, err := http.Get("http://indigo.ciphrtxt.com:7754/api/header/list/since/0")
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    s := new(THeaderListResponse)
    err = json.Unmarshal(body, &s)
    if(err != nil){
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    count := int(0)
    for _, hdr := range s.HeaderList {
        h := new(RawMessageHeader)
        h.Deserialize(hdr)
        hdr_out := h.Serialize()
        hdr_bin := h.ExportBinaryHeaderV2()
        if hdr_bin == nil {
            continue
        }
        hh := ImportBinaryHeaderV2(hdr_bin[:])
        count += 1
        
        if hdr != hdr_out {
            fmt.Println("hdr mismatch!")
            fmt.Println(" in  : " + hdr)
            fmt.Println(" out : " + hdr_out)
            fmt.Println()
            t.Fail()
        }
        
        if hh.Serialize() != hdr_out {
            fmt.Println("hdr mismatch!")
            fmt.Println(" in  : " + hh.Serialize())
            fmt.Println(" out : " + hdr_out)
            fmt.Println()
            t.Fail()
        }
        
        if hdr_bin != nil {
            b64 := base64.StdEncoding.EncodeToString(hdr_bin[:])
            if hdr != hdr_out {
                fmt.Println("binary hdr mismatch!")
                fmt.Println(" bin : " + b64)
                fmt.Println(" out : " + hdr_out)
                fmt.Println()
                t.Fail()
            }
        }
    
        servertime := uint32(time.Now().Unix())
        dbk, err := h.dbKeys(servertime)
        if(err != nil){
            fmt.Println("whoops:", err)
            t.Fail()
        }
        //fmt.Println(hdr)
        //fmt.Println("    " + hex.EncodeToString(dbk.date))
        //fmt.Println("    " + hex.EncodeToString(dbk.servertime))
        //fmt.Println("    " + hex.EncodeToString(dbk.expire))
        //fmt.Println("    " + hex.EncodeToString(dbk.I))
        //fmt.Println()
        
        t64, err := strconv.ParseUint(hex.EncodeToString(dbk.date)[2:10], 16, 32)
        time := uint32(t64)
        if (h.time != time) || (hex.EncodeToString(h.I) != hex.EncodeToString(dbk.date)[10:76]) {
            fmt.Printf("date key mismatch\n")
            t.Fail()
        }
        
        if (hex.EncodeToString(h.I) != hex.EncodeToString(dbk.servertime)[10:76]) {
            fmt.Printf("servertime key mismatch\n")
            t.Fail()
        }
        
        t64, err = strconv.ParseUint(hex.EncodeToString(dbk.expire)[2:10], 16, 32)
        expire := uint32(t64)
        if (h.expire != expire) || (hex.EncodeToString(h.I) != hex.EncodeToString(dbk.expire)[10:76]) {
            fmt.Printf("expire key mismatch\n")
            t.Fail()
        }
        
        if hex.EncodeToString(h.I) != hex.EncodeToString(dbk.I) {
            fmt.Printf("I key mismatch\n")
            t.Fail()
        }
    }
}

func TestOpenHeaderCache (t *testing.T) {
    hc1, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc1.Close()

    hc2, err := OpenHeaderCache("indigo.ciphrtxt.com", 7754, "testdb/indigo.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc2.Close()
}

func TestHeaderCacheGetTime (t *testing.T) {
    hc1, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc1.Close()

    hctime, err := hc1.getTime()
    if err != nil {
        t.Fail()
    }
    
    now := time.Now().Unix()
    diff := int64(hctime) - now
    if diff < 0 {
        diff = 0 - diff
    }
    
    if diff > 5 {
        t.Fail()
    }
}

func TestHeaderCacheGetHeaders (t *testing.T) {
    hc1, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc1.Close()

    now := time.Now().Unix()
    mh, err := hc1.getHeadersSince(uint32(now-3600))
    if err != nil {
        t.Fail()
    }
    
    if len(mh) == 0 {
        t.Fail()
    }
    
    //fmt.Printf("found %d headers\n", len(mh))
    //for _, h := range mh {
    //    fmt.Println(h.Serialize())
    //}
}

func TestHeaderCacheSync (t *testing.T) {
    hc1, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc1.Close()

    err = hc1.Sync()
    if err != nil {
        t.Fail()
    }
    
    //fmt.Printf("found %d headers\n", len(mh))
    //for _, h := range mh {
    //    fmt.Println(h.Serialize())
    //}
}

func TestHeaderGoroutines (t *testing.T) {
    var wg sync.WaitGroup

    hc1, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc1.Close()

    wg.Add(20)
    for gr := 0 ; gr < 20 ; gr++ {
    
        go func(hc *HeaderCache, gr int) {
            defer wg.Done()
            fmt.Printf("in GR %d\n", gr)
            for i := 0 ; i < 20 ; i++ {
                //fmt.Printf("in GR %d i = %d\n", gr, i)
                ago := int64(rand.Intn(60*60*24*7))

                _, err := hc.FindSince(uint32(time.Now().Unix() - ago))
                if err != nil {
                    t.Fail()
                }

                //fmt.Printf("GR %d : fetched %d\n", gr, len(hdrs))
            }
            
            fmt.Printf("GR %d done\n", gr)
        }(hc1, gr)
    }
    wg.Wait()
    
    //fmt.Printf("found %d headers\n", len(mh))
    //for _, h := range mh {
    //    fmt.Println(h.Serialize())
    //}
}

func TestTimes (t *testing.T) {
    hc, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc.Close()

    // last hour as golang time.Time, with a 1 minute propagation time margin
    startTime := time.Now().Add(time.Duration(-61 * time.Minute))
    // messages should expire after startTime + 7 days
    expireTime := startTime.Add(time.Duration((7 * 24) * time.Hour))

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
        if h.MessageTime().Before(startTime) {
            fmt.Println("Message before Start")
            fmt.Println("Start  : " + startTime.Format("Mon Jan _2 15:04:05 2006"))
            fmt.Println("Message: " + h.MessageTime().Format("Mon Jan _2 15:04:05 2006"))
            t.Fail()
        }
        if h.ExpireTime().Before(expireTime) {
            fmt.Println("Expire before + 7d")
            fmt.Println("Expire : " + expireTime.Format("Mon Jan _2 15:04:05 2006"))
            fmt.Println("Now + 7: " + h.ExpireTime().Format("Mon Jan _2 15:04:05 2006"))
            t.Fail()
        }
    }
    
}

func TestHashvals (t *testing.T) {
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
        hx := hex.EncodeToString(h.Hash())
        if hx[:4] != "0000" {
            fmt.Println("Found Message Hash: " + hx)
            t.Fail()
        }
    }
}

func TestSortRawMessageHeader (t *testing.T) {
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
    
    mhs := RawMessageHeaderSlice(mh)
    fmt.Printf("Sorting %d elements\n", mhs.Len())
    
    for _, h := range mhs {
        fmt.Printf("t %d : I %s\n", h.time, hex.EncodeToString(h.I))
        hx := hex.EncodeToString(h.Hash())
        if hx[:4] != "0000" {
            fmt.Println("Found Message Hash: " + hx)
            t.Fail()
        }
    }
    
    fmt.Println()
    
    sort.Sort(mhs)
    
    for _, h := range mhs {
        fmt.Printf("t %d : I %s\n", h.time, hex.EncodeToString(h.I))
        hx := hex.EncodeToString(h.Hash())
        if hx[:4] != "0000" {
            fmt.Println("Found Message Hash: " + hx)
            t.Fail()
        }
    }
    
    fmt.Println()
    
    sort.Sort(sort.Reverse(RawMessageHeaderSlice(mh)))
    
    for _, h := range mhs {
        fmt.Printf("t %d : I %s\n", h.time, hex.EncodeToString(h.I))
        hx := hex.EncodeToString(h.Hash())
        if hx[:4] != "0000" {
            fmt.Println("Found Message Hash: " + hx)
            t.Fail()
        }
    }
}

func TestFindByI (t *testing.T) {
    hc, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc.Close()

    res, err := http.Get("http://ciphrtxt.com:7754/api/header/list/since/0")
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    s := new(THeaderListResponse)
    err = json.Unmarshal(body, &s)
    if(err != nil){
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    for _, hdr := range s.HeaderList {
        h := new(RawMessageHeader)
        h.Deserialize(hdr)
        
        msg, err := hc.FindByI(h.IKey())
        if err != nil {
            if uint32(time.Now().Unix()) < h.expire {
                fmt.Println("Error: could not find message:", h.I)
                t.Fail()
            }
        } else if msg.Serialize() != h.Serialize() {
            fmt.Println("Error: message mismatch:", h.I)
            t.Fail()
        }
    }
}

func TestLocalHeaderCache (t *testing.T) {
    lhc, err := OpenLocalHeaderCache("headers")
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    defer lhc.Close()
    
    lhc.AddPeer("indigo.ciphrtxt.com",7754)
    lhc.AddPeer("violet.ciphrtxt.com",7754)
    
    lhc.Sync()
    
    for i := 60 ; i > 0 ; i-- {
        fmt.Printf("\rsleeping %d seconds  ", i)
        time.Sleep(time.Second * 1)
    }
    fmt.Println(" ... done")
    
    lhc.Sync()
}

func TestLocalFindByI (t *testing.T) {
    lhc, err := OpenLocalHeaderCache("headers")
    if err != nil {
        t.Fail()
    }
    defer lhc.Close()

    res, err := http.Get("http://ciphrtxt.com:7754/api/header/list/since/0")
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    s := new(THeaderListResponse)
    err = json.Unmarshal(body, &s)
    if(err != nil){
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    lhc.Sync()
    
    for _, hdr := range s.HeaderList {
        h := new(RawMessageHeader)
        h.Deserialize(hdr)
        
        msg, err := lhc.FindByI(h.IKey())
        if err != nil {
            if uint32(time.Now().Unix()) < h.expire {
                fmt.Println("Error: could not find message:", hex.EncodeToString(h.IKey()))
                t.Fail()
            }
        } else if msg.Serialize() != h.Serialize() {
            fmt.Println("Error: message mismatch:", hex.EncodeToString(h.IKey()))
            t.Fail()
        }
    }
}

func TestLocalFindSector (t *testing.T) {
    var ring uint

    lhc, err := OpenLocalHeaderCache("headers")
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    defer lhc.Close()

    oneHrAgo := uint32(time.Now().Unix() - (60*60))
    
    for r := 9; r >= 0; r-- {
        ring = uint(r)
        start := rand.Intn(0x200) + 0x200
        ringsz := 512 >> ring
        end := start + ringsz
        
        allHeaders, err := lhc.FindSince(oneHrAgo)
        if err != nil {
            fmt.Println("whoops:", err)
            t.Fail()
        }
        
        seg := ShardSector {
            Start: start,
            Ring: ring,
        }
        segHeaders, err := lhc.findSector(seg)
        if err != nil {
            fmt.Println("whoops:", err)
            t.Fail()
        }
        
        if (segHeaders != nil) {
            for _, s := range segHeaders {
                i64, err := strconv.ParseUint(hex.EncodeToString(s.I)[:4], 16, 64)
                if err != nil {
                    fmt.Println("whoops:", err)
                    t.Fail()
                }
                i := int(i64)
                if end > 0x400 {
                    if (i < start) && (i >= (end - 0x200)) {
                        fmt.Printf("Error, %d outside of range [%d, %d)\n", i, start, end)
                        t.Fail()
                    }
                } else {
                    if (i < start) || (i >= end) {
                        fmt.Printf("Error, %d outside of range [%d, %d)\n", i, start, end)
                        t.Fail()
                    }
                }
                contains, err := seg.Contains(s.I)
                if err != nil {
                    fmt.Println("whoops:", err)
                    t.Fail()
                }
                if contains == false {
                    fmt.Printf("Error, %d outside of range [%d, %d)\n", i, start, end)
                    t.Fail()
                }
            }
            
            if (allHeaders != nil) {
                for _, h := range allHeaders {
                    var found bool = false
                
                    i64, err := strconv.ParseUint(hex.EncodeToString(h.I)[:4], 16, 64)
                    if err != nil {
                        t.Fail()
                    }
                    i := int(i64)
                    if end > 0x400 {
                        if (i < start) && (i >= (end - 0x200)) {
                            continue
                        }
                    } else {
                        if (i < start) || (i >= end) {
                            continue
                        }
                    }
                    
                    //fmt.Printf("Seeking %04x - %s for range [%04x, %04x)\n", i, string(h.I), start, end)
                    
                    for _, s := range segHeaders {
                        if s.time < oneHrAgo {
                            continue
                        }
                        
                        if bytes.Equal(s.I, h.I) {
                            found = true
                            break
                        }
                    }
                    if found == false {
                        if h.time > oneHrAgo {
                            fmt.Printf("Error, %04x, %s not found for range [%04x, %04x)\n", i, string(h.I), start, end)
                            t.Fail()
                        }
                    }
                }
            }
        }
    }
}

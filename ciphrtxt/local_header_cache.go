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
    //"net/http"
    //"io/ioutil"
    "encoding/hex"
    //"encoding/json"
    "fmt"
    "errors"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/syndtr/goleveldb/leveldb/util"
    "math/rand"
    "strconv"
    "sync"
    "time"
)

const lhcRefreshMinDelay = 10
const lhcPeerConsecutiveErrorMax = 20
const lhcPeerInfoMinDelay = 300

type peerCache struct {
    hc    *HeaderCache
    lastRefresh   uint32
    lastGetPeers  uint32
}

type peerCandidate struct {
    host   string
    port   uint16
}

type LocalHeaderCache struct {
    basepath string
    db *leveldb.DB
    syncMutex sync.Mutex
    syncInProgress bool
    serverTime uint32
    lastRefresh uint32
    Count int
    Peers []*peerCache
    peerCandidateMutex sync.Mutex
    peerCandidates []*peerCandidate
    discoverPeersMutex sync.Mutex
    discoverPeersInProgress bool
}

func OpenLocalHeaderCache(filepath string) (lhc *LocalHeaderCache, err error) {
    lhc = new(LocalHeaderCache)
    lhc.basepath = filepath
    
    dbpath := filepath + "/localdb"
    
    if len(dbpath) == 0 {
        return nil, errors.New("refusing to open empty db path")
    }
    
    lhc.db, err = leveldb.OpenFile(dbpath, nil)
    if err != nil { return nil, err }
    
    err = lhc.recount()
    if err != nil { return nil, err }
    
    fmt.Printf("LocalHeaderCache open, found %d message headers\n", lhc.Count)
    return lhc, nil
}

func (lhc *LocalHeaderCache) recount() (err error) {
    emptyMessage := "000000000000000000000000000000000000000000000000000000000000000000"
    
    expiredBegin, err := hex.DecodeString("E0" + "00000000" + emptyMessage)
    if err != nil { return err }
    
    expiredEnd, err := hex.DecodeString("E0" + "FFFFFFFF" + emptyMessage)
    if err != nil { return err }
    
    iter := lhc.db.NewIterator(&util.Range{Start: expiredBegin,Limit: expiredEnd}, nil)

    count := int(0)
        
    for iter.Next() {
        count += 1
    }
    iter.Release()

    lhc.Count = count
    
    return nil
}

func (lhc *LocalHeaderCache) Close() {
    for _, p := range lhc.Peers {
        if p.hc != nil {
            p.hc.Close()
            p.hc = nil
        }
    }
    
    if lhc.db != nil {
        lhc.db.Close()
        lhc.db = nil
    }
}

func (lhc *LocalHeaderCache) Insert(h *RawMessageHeader) (insert bool, err error) {
    servertime := uint32(time.Now().Unix())
    
    dbk, err := h.dbKeys(servertime)
    if err != nil { return false, err }
    
    _, err = lhc.db.Get(dbk.I, nil)
    if err == nil { return false, nil }
    
    value := []byte(h.Serialize())
    
    batch := new(leveldb.Batch)
    batch.Put(dbk.date, value)
    batch.Put(dbk.servertime, value)
    batch.Put(dbk.expire, value)
    batch.Put(dbk.I, value)
    
    err = lhc.db.Write(batch, nil)
    if err != nil { return false, err }
    
    lhc.Count += 1
    return true, nil
}

func (lhc *LocalHeaderCache) Remove(h *RawMessageHeader) (err error) {
    value, err := lhc.db.Get(h.I, nil)
    if err != nil {
        return err
    }
    servertime := deserializeUint32(value[MessageHeaderLengthV2:MessageHeaderLengthV2+4])
    dbk, err := h.dbKeys(servertime)
    if err != nil {
        return err
    }
    batch := new(leveldb.Batch)
    batch.Delete(dbk.date)
    batch.Delete(dbk.servertime)
    batch.Delete(dbk.expire)
    batch.Delete(dbk.I)
    lhc.Count -= 1
    return lhc.db.Write(batch, nil)
}

func (lhc *LocalHeaderCache) FindByI (I []byte) (h *RawMessageHeader, err error) {
    lhc.Sync()

    value, err := lhc.db.Get(I, nil)
    if err != nil {
        return nil, err
    }
    h = new(RawMessageHeader)
    if h.Deserialize(string(value)) == nil {
        return nil, errors.New("retreived invalid header from database")
    }
    return h, nil
}

func (lhc *LocalHeaderCache) FindSince (tstamp uint32) (hdrs []RawMessageHeader, err error) {
    lhc.Sync()

    emptyMessage := "000000000000000000000000000000000000000000000000000000000000000000"
    tag1 := fmt.Sprintf("C0%08X%s", tstamp, emptyMessage)
    tag2 := "C0" + "FFFFFFFF" + emptyMessage
    
    bin1, err := hex.DecodeString(tag1)
    if err != nil {
        return nil, err
    }
    bin2, err := hex.DecodeString(tag2)
    if err != nil {
        return nil, err
    }
    
    iter := lhc.db.NewIterator(&util.Range{Start: bin1, Limit: bin2}, nil)
    
    hdrs = make([]RawMessageHeader, 0)
    for iter.Next() {
        h := new(RawMessageHeader)
        if h.Deserialize(string(iter.Value())) == nil {
            return nil, errors.New("error parsing message")
        }
        hdrs = append(hdrs, *h)
    }
    return hdrs, nil
}

func (lhc *LocalHeaderCache) findSector (seg ShardSector) (hdrs []RawMessageHeader, err error) {
    var tag1, tag2, tag3, tag4 string
    var bin1, bin2, bin3, bin4 []byte
    
    start := seg.Start
    ring := seg.Ring

    lhc.Sync()
    
    //fmt.Printf("LocalHeaderCache.findSector %04x, %d\n", start, ring)

    if ((start < 0x0200) || (start > 0x03ff)) {
        return nil, fmt.Errorf("LocalHeaderCache.findSector start value out of range")
    }

    if ((ring < 0) || (ring > 9)) {
        return nil, fmt.Errorf("LocalHeaderCache.findSector ring value out of range")
    }

    ringsz := 512 >> ring
    end := start + ringsz
    
    emptyMessage := "00000000000000000000000000000000000000000000000000000000000000"
    tag1 = fmt.Sprintf("%04X%s", start, emptyMessage)
    
    if end > 0x400 {
        tag2 = fmt.Sprintf("0400%s", emptyMessage)
        tag3 = fmt.Sprintf("0000%s", emptyMessage)
        tag4 = fmt.Sprintf("%04X%s", ((end & 0x03FF) | (0x0200)) , emptyMessage)
        
        //fmt.Printf("fs: tag1 = %s\n", tag1)
        //fmt.Printf("fs: tag2 = %s\n", tag2)
        //fmt.Printf("fs: tag3 = %s\n", tag3)
        //fmt.Printf("fs: tag4 = %s\n", tag4)
        
        bin3, err = hex.DecodeString(tag3)
        if err != nil {
            return nil, err
        }
        bin4, err = hex.DecodeString(tag4)
        if err != nil {
            return nil, err
        }
    } else {
        tag2 = fmt.Sprintf("%04X%s", end, emptyMessage)
        
        //fmt.Printf("fs: tag1 = %s\n", tag1)
        //fmt.Printf("fs: tag2 = %s\n", tag2)
    }
    
    bin1, err = hex.DecodeString(tag1)
    if err != nil {
        return nil, err
    }
    bin2, err = hex.DecodeString(tag2)
    if err != nil {
        return nil, err
    }
    
    iter := lhc.db.NewIterator(&util.Range{Start: bin1, Limit: bin2}, nil)
    
    hdrs = make([]RawMessageHeader, 0)
    for iter.Next() {
        h := new(RawMessageHeader)
        if h.Deserialize(string(iter.Value())) == nil {
            return nil, errors.New("error parsing message")
        }
        hdrs = append(hdrs, *h)
    }
    
    if (end > 0x400) {
        iter := lhc.db.NewIterator(&util.Range{Start: bin3, Limit: bin4}, nil)
    
        for iter.Next() {
            h := new(RawMessageHeader)
            if h.Deserialize(string(iter.Value())) == nil {
                return nil, errors.New("error parsing message")
            }
            hdrs = append(hdrs, *h)
        }
    }
    
    //fmt.Printf("found %d headers\n", len(hdrs))
    return hdrs, nil
}

func (lhc *LocalHeaderCache) FindExpiringAfter (tstamp uint32) (hdrs []RawMessageHeader, err error) {
    lhc.Sync()

    emptyMessage := "000000000000000000000000000000000000000000000000000000000000000000"
    tag1 := fmt.Sprintf("E0%08X%s", tstamp, emptyMessage)
    tag2 := "E0" + "FFFFFFFF" + emptyMessage
    
    bin1, err := hex.DecodeString(tag1)
    if err != nil {
        return nil, err
    }
    bin2, err := hex.DecodeString(tag2)
    if err != nil {
        return nil, err
    }
    
    iter := lhc.db.NewIterator(&util.Range{Start: bin1, Limit: bin2}, nil)
    
    hdrs = make([]RawMessageHeader, 0)
    for iter.Next() {
        h := new(RawMessageHeader)
        if h.Deserialize(string(iter.Value())) == nil {
            return nil, errors.New("error parsing message")
        }
        hdrs = append(hdrs, *h)
    }
    return hdrs, nil
}

func (lhc *LocalHeaderCache) getTime() (serverTime uint32, err error) {
    lhc.serverTime = uint32(time.Now().Unix())
    return lhc.serverTime, nil
}

func (lhc *LocalHeaderCache) pruneExpired() (err error) {
    emptyMessage := "000000000000000000000000000000000000000000000000000000000000000000"
    expiredBegin, err := hex.DecodeString("E0" + "00000000" + emptyMessage)
    if err != nil {
        return err
    }
    now := strconv.FormatUint(uint64(time.Now().Unix()),16)
    expiredEnd, err := hex.DecodeString("E0" + now + emptyMessage)
    if err != nil {
        return err
    }

    iter := lhc.db.NewIterator(&util.Range{Start: expiredBegin,Limit: expiredEnd}, nil)
    batch := new(leveldb.Batch)
    hdr := new(RawMessageHeader)
    
    delCount := int(0)
        
    for iter.Next() {
        value := iter.Value()
        if hdr.Deserialize(string(value)) == nil {
            return errors.New("unable to parse database value")
        }
        servertime := deserializeUint32(value[MessageHeaderLengthV2:MessageHeaderLengthV2+4])
        dbk, err := hdr.dbKeys(servertime)
        if err != nil {
            return err
        }
        batch.Delete(dbk.date)
        batch.Delete(dbk.servertime)
        batch.Delete(dbk.expire)
        batch.Delete(dbk.I)
        delCount += 1
    }
    iter.Release()
    
    err = lhc.db.Write(batch, nil)
    if err == nil {
        lhc.Count -= delCount
        fmt.Printf("LocalHeaderCache: dropping %d message headers\n", delCount)
    }
    
    return err
}

func (lhc *LocalHeaderCache) Sync() (err error) {
    // if "fresh enough" (refreshMinDelay) then simply return
    now := uint32(time.Now().Unix())
    
    if (lhc.lastRefresh + lhcRefreshMinDelay) > now {
        return nil
    }
    
    //should only have a single goroutine sync'ing at a time
    lhc.syncMutex.Lock()
    if lhc.syncInProgress {
        lhc.syncMutex.Unlock()
        return nil
    }
    lhc.syncInProgress = true
    lhc.syncMutex.Unlock()
    defer func(lhc *LocalHeaderCache) {
        lhc.syncInProgress = false
    }(lhc)
    
    //copy and reset candidates list
    lhc.peerCandidateMutex.Lock()
    candidates := lhc.peerCandidates
    lhc.peerCandidates = make([]*peerCandidate, 0)
    lhc.peerCandidateMutex.Unlock()
    
    for _, pc := range candidates {
        if lhc.addPeer(pc.host, pc.port) != nil {
            fmt.Printf("LocalHeaderCache: failed to add peer %s, %d\n", pc.host, pc.port)
        }
    }
    
    err = lhc.pruneExpired()
    if err != nil {
        return err
    }
    
    insCount := int(0)
    
    // NOTE: lhc.Peers can grow outside this function... if the list gets longer any past nPeers
    // in the list will not get refreshed this round. The list is only truncated further below
    // and processing within sync is serialized by a mutex so the list can't shrink during the loop
    nPeers := len(lhc.Peers)
    ordinal := rand.Perm(nPeers)
    for i := 0 ; i < nPeers ; i++ {
        p := lhc.Peers[ordinal[i]]
        fmt.Printf("%d : %s:%d\n", ordinal[i], p.hc.host, p.hc.port)
    }
    fmt.Printf("\n")
    for i := 0; i < nPeers ; i++ {
        p := lhc.Peers[ordinal[i]]
        
        p.hc.Sync()
        
        lastRefreshPeer := p.hc.lastRefreshServer
        
        if lastRefreshPeer > p.lastRefresh {
            mhdrs, err := p.hc.FindSince(p.lastRefresh)
            if err != nil { return err }
    
            insCount := int(0)

            for _, mh := range mhdrs {
                insert, err := lhc.Insert(&mh)
                if err != nil {
                    return err
                }
                if insert {
                    insCount += 1
                }
            }
            
            p.lastRefresh = lastRefreshPeer
            
            fmt.Printf("LocalHeaderCache: inserted %d message headers\n", insCount)    
        }
    }
    
    newPeers := make([]*peerCache, 0, len(lhc.Peers))
    for _, p := range lhc.Peers {
        if p.hc.NetworkErrors < lhcPeerConsecutiveErrorMax {
            newPeers = append(newPeers, p)
        } else {
            fmt.Printf("LocalHeaderCache: dropping peer %s (error count too high)\n", p.hc.baseurl)
        }
    }
    
    lhc.Peers = newPeers

    lhc.lastRefresh = now

    lhc.Count += insCount
    fmt.Printf("LocalHeaderCache: insert %d message headers\n", insCount)
    
    fmt.Printf("LocalHeaderCache: %d active message headers\n", lhc.Count)

    return nil
}

func (lhc *LocalHeaderCache) AddPeer(host string, port uint16) {
    //should only have a single goroutine sync'ing at a time
    lhc.peerCandidateMutex.Lock()
    defer lhc.peerCandidateMutex.Unlock()
    
    pc := new(peerCandidate)
    pc.host = host
    pc.port = port
    
    lhc.peerCandidates = append(lhc.peerCandidates, pc)
}

func (lhc *LocalHeaderCache) addPeer(host string, port uint16) (err error) {
    for _, p := range lhc.Peers {
        if (p.hc.host == host) && (p.hc.port == port) {
            return nil
        }
    }
    
    dbpath := lhc.basepath + "/remote/" + host + "_" + strconv.Itoa(int(port)) + "/hdb"
    
    pc := new(peerCache)
    
    rhc, err := OpenHeaderCache(host, port, dbpath)
    if err != nil {
        return err
    }
    
    err = rhc.Sync()
    if err != nil {
        return err
    }
    
    lastRefresh := rhc.lastRefreshServer
    
    mhdrs, err := rhc.FindSince(0)
    if err != nil {
        return err
    }
    
    pc.hc = rhc
    pc.lastRefresh = lastRefresh
    
    lhc.Peers = append(lhc.Peers, pc)

    insCount := int(0)

    for _, mh := range mhdrs {
        insert, err := lhc.Insert(&mh)
        if err != nil {
            return err
        }
        if insert {
            insCount += 1
        }
    }
    
    fmt.Printf("LocalHeaderCache: inserted %d message headers\n", insCount)

    //lhc.recount()
    
    fmt.Printf("LocalHeaderCache: %d active message headers\n", lhc.Count)

    return nil
}

func (lhc *LocalHeaderCache) ListPeers() (plr []PeerItemResponse) {
    plr = make([]PeerItemResponse,0)
    for _, p := range lhc.Peers {
        pir := new(PeerItemResponse)
        pir.Host = p.hc.host
        pir.Port = p.hc.port
        plr = append(plr, *pir)
    }
    return plr
}

func (lhc *LocalHeaderCache) DiscoverPeers(exthost string, extport uint16) (err error) {
    //should only have a single goroutine running discovery at a time
    lhc.discoverPeersMutex.Lock()
    if lhc.discoverPeersInProgress {
        lhc.discoverPeersMutex.Unlock()
        return nil
    }
    lhc.discoverPeersInProgress = true
    lhc.discoverPeersMutex.Unlock()
    defer func(lhc *LocalHeaderCache) {
        lhc.discoverPeersInProgress = false
    }(lhc)
    
    now := uint32(time.Now().Unix())

    for _, p := range lhc.Peers {
        if (p.lastGetPeers + lhcPeerInfoMinDelay) < now {
            if p.hc.getPeerInfo() == nil {
                p.lastGetPeers = now
        
                needsLocal := true
                for _, remote := range p.hc.PeerInfo {
                    remoteNew := true
                    for _, local := range lhc.Peers {
                        if (local.hc.host == remote.Host) && (local.hc.port == remote.Port) {
                            remoteNew = false
                            break
                        }
                    }
                    if (remote.Host == exthost) && (remote.Port == extport) {
                        needsLocal = false
                    } else {
                        if remoteNew {
                            lhc.addPeer(remote.Host, remote.Port)
                        }
                    }
                }
                if needsLocal {
                    p.hc.postPeerInfo(exthost, extport)
                }
            }
        }
    }

    return nil
}

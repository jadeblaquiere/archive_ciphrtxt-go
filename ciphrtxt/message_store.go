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
    //"io"
    "io/ioutil"
    //"encoding/binary"
    "encoding/hex"
    //"encoding/json"
    "fmt"
    "errors"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/syndtr/goleveldb/leveldb/util"
    "math/rand"
    "os"
    "strconv"
    "sync"
    "time"
)

// 15 minutes clock skew - don't retry downloads of messages which fail
// and expire within this time

const allowableClockSkew = (60*15)

const syncMaxGoroutines = 32

type MessageStore struct {
    rootpath string
    db *leveldb.DB
    syncMutex sync.Mutex
    syncInProgress bool
    Count int
    sector ShardSector
    target ShardSector
    lastRefresh uint32
    syncwg sync.WaitGroup
    iqueue chan []byte
    quitchan []chan int
    LHC *LocalHeaderCache
}

func CheckOrCreateDirectory (filepath string) (err error) {
    finfo, err := os.Stat(filepath)
    if os.IsNotExist(err) {
        return os.Mkdir(filepath, os.FileMode(0755))
    }
    
    if !finfo.IsDir() {
        return fmt.Errorf("Expected Directory, got file for %s", filepath)
    }
    
    return nil
}

func (ms *MessageStore) fetchMessageFromPeers(I []byte) (m *MessageFile) {
    nPeers := len(ms.LHC.Peers)
    ordinal := rand.Perm(nPeers)
    for i := 0; i < nPeers; i++ {
        phc := ms.LHC.Peers[ordinal[i]].HC
        sector := phc.status.Sector
        if !sector.Contains(I) {
            continue
        }
        h, _ := phc.FindByI(I)
        if h == nil {
            fmt.Printf("err: not found\n")
            continue
        }
        tmptime := time.Now().UnixNano()
        recvpath := ms.rootpath + "/receive/"+ strconv.Itoa(int(tmptime))
        //fmt.Printf("saving to to %s\n", recvpath)
        //fmt.Printf("GR%d: pulling %s from %s as %s\n",gr,hex.EncodeToString(I), phc.baseurl, recvpath)
        m, err := phc.tryDownloadMessage(I, recvpath)
        if err != nil {
            fmt.Printf("MS: download error getting %s from %s Error: %s\n", hex.EncodeToString(I), phc.baseurl, err)
            continue
        }
        Ihex := hex.EncodeToString(I)
        filemove := ms.rootpath + "/store/" + Ihex[:4] + "/" + Ihex
        //fmt.Printf("moving to %s\n", filemove)
        err = m.Move(filemove)
        if err != nil {
            fmt.Printf("err: move \n")
            continue
        }
        _, err = ms.Insert(m)
        if err != nil {
            fmt.Printf("err: Insert\n")
            continue
        }
        return m
    }
    return nil
}

func OpenMessageStore(filepath string, lhc *LocalHeaderCache, startbin int) (ms *MessageStore, err error) {
    err = CheckOrCreateDirectory(filepath)
    if err != nil {
        return nil, err
    }
    
    err = CheckOrCreateDirectory(filepath + "/store")
    if err != nil {
        return nil, err
    }
    
    err = CheckOrCreateDirectory(filepath + "/receive")
    if err != nil {
        return nil, err
    }
    
    ms = new(MessageStore)
    ms.rootpath = filepath
    ms.sector.Start = startbin
    ms.sector.Ring = ShardSectorOuterRing
    ms.LHC = lhc
    
    ms.iqueue = make(chan []byte, (5*syncMaxGoroutines))
    ms.quitchan = make([]chan int, syncMaxGoroutines)
    
    ms.syncwg.Add(syncMaxGoroutines)
    for gr := 0 ; gr < syncMaxGoroutines ; gr++ {
        ms.quitchan[gr] = make(chan int)
        go func(ms *MessageStore, Iqueue chan []byte, cquit chan int, gr int) {
            defer ms.syncwg.Done()
            //fmt.Printf("in GR %d\n", gr)
            for {
                select {
                case I := <- Iqueue:
                    m := ms.fetchMessageFromPeers(I)
                    if m == nil {
                        h, err := ms.LHC.FindByI(I)
                        if err == nil {
                            if (h.expire + allowableClockSkew) > uint32(time.Now().Unix()) {
                                fmt.Printf("GR%d: failing I (%s) dropping from queue\n", gr, hex.EncodeToString(I))
                                //fmt.Printf("GR%d: pushing I (%s) back onto queue\n", gr, hex.EncodeToString(I))
                                // push back on the queue
                                //Iqueue <- I
                            }
                        }
                    }
                case <- cquit:
                    //fmt.Printf("GR %d done\n", gr)
                    return
                }
            }
        }(ms, ms.iqueue, ms.quitchan[gr], gr)
    }
    fmt.Printf("MS: Started %d download goroutines\n", syncMaxGoroutines)
    
    ms.db, err = leveldb.OpenFile(filepath + "/msgdb", nil)
    if err != nil {
        return nil, err
    }
    
    for i := 0x200; i < 0x400; i++ {
        p := fmt.Sprintf("%s/store/%04x", filepath, i)
        err = CheckOrCreateDirectory(p)
        if err != nil {
            return nil, err
        }
        
        files, err := ioutil.ReadDir(p)
        if err != nil {
            return nil, err
        }
        
        for _, f := range files {
            //fmt.Printf("Found file %s in %s\n", f.Name(), p)
            dbkey, err := hex.DecodeString(f.Name())
            if err != nil {
                fmt.Printf("Error parsing %s as hex\n", f.Name())
                continue
            }
            _, err = ms.db.Get(dbkey, nil)
            if err != nil {
                //fmt.Printf("%s not found in db, inserting\n", f.Name())
                fpath := p + "/" + f.Name()
                //ins, err := ms.InsertFile(fpath)
                _, err := ms.InsertFile(fpath)
                if err != nil {
                    fmt.Printf("Failed to insert message %s\n", fpath)
                    continue
                }
                //if ins != 0 {
                //    fmt.Printf("inserted %s into db\n", f.Name())
                //}
            }
        }
    }
    
    ms.pruneExpired()
    
    err = ms.recount()
    if err != nil {
        return nil, err
    }
    
    err = ms.syncLHC()
    if err != nil {
        return nil, err
    }
    
    fmt.Printf("MessageStore open, found %d messages\n", ms.Count)
    return ms, nil
}

func (ms *MessageStore) Close() {
    fmt.Printf("MessageStore:Close : sending close to all goroutines\n")
    //send quit to all workers
    for _, c := range ms.quitchan {
        c <- 0
    }
    fmt.Printf("MessageStore:Close : close sent to all goroutines, waiting\n")
    ms.syncwg.Wait()
    fmt.Printf("MessageStore:Close : all goroutines completed\n")
    if ms.db != nil {
        ms.db.Close()
        ms.db = nil
    }
}

func (ms *MessageStore) recount() (err error) {
    emptyMessage := "000000000000000000000000000000000000000000000000000000000000000000"
    expiredBegin, err := hex.DecodeString("E0" + "00000000" + emptyMessage)
    if err != nil {
        return err
    }
    expiredEnd, err := hex.DecodeString("E0" + "FFFFFFFF" + emptyMessage)
    if err != nil {
        return err
    }
    
    iter := ms.db.NewIterator(&util.Range{Start: expiredBegin,Limit: expiredEnd}, nil)

    count := int(0)
        
    for iter.Next() {
        count += 1
    }
    iter.Release()

    ms.Count = count
    
    return nil
}

func (ms *MessageStore) syncLHC() (err error) {
    lhc := ms.LHC

    emptyMessage := "0000000000000000000000000000000000000000000000000000000000000000"
    iBegin, err := hex.DecodeString("02" + emptyMessage)
    if err != nil {
        return err
    }
    iEnd, err := hex.DecodeString("04" + emptyMessage)
    if err != nil {
        return err
    }
    
    iter := ms.db.NewIterator(&util.Range{Start: iBegin,Limit: iEnd}, nil)

    for iter.Next() {
        _, err := lhc.FindByI(iter.Key())
        if err != nil {
            m := new(MessageFile)
            value := iter.Value()
            if m.Deserialize(value) == nil {
                return errors.New("error parsing message value from database")
            }
            _, err := lhc.Insert(&(m.RawMessageHeader))
            if err != nil {
                return err
            }
        }
    }
    iter.Release()

    return nil
}

func (ms *MessageStore) InsertFile(filepath string) (servertime uint32, err error) {
    m := Ingest(filepath)
    if m == nil {
        return 0, fmt.Errorf("Ingest failed for %s\n", filepath)
    }
    return ms.Insert(m)
}

func (ms *MessageStore) Insert(m *MessageFile) (servertime uint32, err error) {
    dbk, err := m.RawMessageHeader.dbKeys(m.Servertime)
    if err != nil {
        return 0, err
    }
    previous, err := ms.db.Get(dbk.I, nil)
    if err == nil {
        p := new(MessageFile)
        if p.Deserialize(previous) == nil {
            return 0, errors.New("retreived invalid message from database")
        }
        return p.Servertime, nil
    }
    value := []byte(m.Serialize())
    batch := new(leveldb.Batch)
    batch.Put(dbk.servertime, value)
    batch.Put(dbk.expire, value)
    batch.Put(dbk.I, value)
    err = ms.db.Write(batch, nil)
    if err != nil {
        return 0, err
    }
    ms.Count += 1
    _, err = ms.LHC.Insert(&(m.RawMessageHeader))
    if err != nil {
        return 0, err
    }
    return m.Servertime, nil
}

func (ms *MessageStore) Remove(m *MessageFile) (err error) {
    dbk, err := m.RawMessageHeader.dbKeys(m.Servertime)
    if err != nil {
        return err
    }
    batch := new(leveldb.Batch)
    batch.Delete(dbk.servertime)
    batch.Delete(dbk.expire)
    batch.Delete(dbk.I)
    err = ms.db.Write(batch, nil)
    if err == nil {
        return os.Remove(m.Filepath)
    }
    ms.Count -= 1
    return err
}

func (ms *MessageStore) FindSince (tstamp uint32) (msgs []MessageFile, err error) {
    ms.Sync()

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
    
    iter := ms.db.NewIterator(&util.Range{Start: bin1, Limit: bin2}, nil)
    
    msgs = make([]MessageFile, 0)
    for iter.Next() {
        m := new(MessageFile)
        value := iter.Value()
        if m.Deserialize(value) == nil {
            return nil, errors.New("error parsing message")
        }
        msgs = append(msgs, *m)
    }
    
    return msgs, nil
}

func (ms *MessageStore) pruneExpired() (err error) {
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

    iter := ms.db.NewIterator(&util.Range{Start: expiredBegin,Limit: expiredEnd}, nil)
    batch := new(leveldb.Batch)
    m := new(MessageFile)
    
    delCount := int(0)
    filesToRemove := make([]string, 0, 1024)
        
    for iter.Next() {
        if m.Deserialize(iter.Value()) == nil {
            return errors.New("unable to parse database value")
        }
        dbk, err := m.RawMessageHeader.dbKeys(m.Servertime)
        if err != nil {
            return err
        }
        batch.Delete(dbk.servertime)
        batch.Delete(dbk.expire)
        batch.Delete(dbk.I)
        delCount += 1
        filesToRemove = append(filesToRemove, m.Filepath)
    }
    iter.Release()
    
    err = ms.db.Write(batch, nil)
    if err != nil {
        return err
    }
    
    ms.Count -= delCount
    //fmt.Printf("MessageStore: dropped %d messages from db\n", delCount)
    
    delCount = 0
    for _, f := range filesToRemove {
        err = os.Remove(f)
        if err == nil {
            delCount += 1
        }
    }
    
    //fmt.Printf("MessageStore: removed %d messages from filesystem\n", delCount)
    
    return nil
}

func (ms *MessageStore) FindByI (I []byte) (m *MessageFile, err error) {
    //ms.Sync()

    value, err := ms.db.Get(I, nil)
    if err != nil {
        return nil, err
    }
    m = new(MessageFile)
    if m.Deserialize(value) == nil {
        return nil, errors.New("retreived invalid message from database")
    }
    return m, nil
}

func (ms *MessageStore) FindOrFetchByI (I []byte) (m *MessageFile, err error) {
    //ms.Sync()

    value, err := ms.db.Get(I, nil)
    if err == nil {
        m = new(MessageFile)
        if m.Deserialize(value) == nil {
            return nil, errors.New("retreived invalid message from database")
        }
    } else {
        m = ms.fetchMessageFromPeers(I)
        if m == nil {
            return nil, errors.New("message not found")
        }
    }
    return m, nil
}

func (ms *MessageStore) syncSector(sector ShardSector) (err error) {
    lhc := ms.LHC
    lhc.Sync()
    
    fmt.Printf("MessageStore.syncSector : refresh %04x-%d\n", sector.Start, sector.Ring)
    
    segHeaders, err := lhc.findSector(sector)
    if err != nil {
        return err
    }
    
    //fmt.Printf("MessageStore.syncSector: %d headers in scope\n", len(segHeaders))
    
    for _, s := range segHeaders {
        if s.version == "0100" {
            continue
        }
        _, err = ms.FindByI(s.I)
        if err != nil {
            //fmt.Printf("MessageStore.syncSector : queueing %s\n", hex.EncodeToString(s.I))
            ms.iqueue <- s.I
        }
    }
    
    return nil
}

func (ms *MessageStore) refreshSector(sector ShardSector, since uint32) (err error) {
    lhc := ms.LHC
    lhc.Sync()
    
    fmt.Printf("MessageStore.refreshSector : refresh %04x-%d\n", sector.Start, sector.Ring)
    
    segHeaders, err := lhc.FindSince(since)
    if err != nil {
        return err
    }
    
    //fmt.Printf("")
    
    for _, s := range segHeaders {
        if s.version == "0100" {
            continue
        }
        if sector.Contains(s.I) {
            _, err = ms.FindByI(s.I)
            if err != nil {
                //fmt.Printf("MessageStore.refreshSector : queueing %s\n", hex.EncodeToString(s.I))
                ms.iqueue <- s.I
            }
        }
    }
    
    return nil
}

func (ms *MessageStore) populate(ring uint) (err error) {
    if ring > ShardSectorOuterRing {
        ring = ShardSectorOuterRing
    }

    newSync := ms.LHC.lastRefresh
    lastSync := ms.LHC.lastRefresh
    currentRing := ms.sector.Ring
    target := ms.sector
    
    // validate that the current sector is covered
    
    ms.syncSector(ms.sector)
    
    // step "down" one ring at a time: add "next" sector; refresh new for combined
    
    for r := currentRing; r > ring; r-- {
        extent := 512 >> r
        target = ShardSector{
            Start: ((ms.sector.Start + extent) & 0x01ff) | 0x0200,
            Ring: r,
        }
    
        ms.syncSector(target)
        
        target = ShardSector{
            Start: ms.sector.Start,
            Ring: r - 1,
        }
        
        newSync = ms.LHC.lastRefresh
        ms.refreshSector(target, lastSync)
        lastSync = newSync
    }
    
    ms.sector = target
    ms.lastRefresh = lastSync
    
    return nil
}

func (ms *MessageStore) SetTarget(target ShardSector) {
    ms.target = target
    ms.sector.Start = target.Start
    ms.sector.Ring = ShardSectorOuterRing
    
    go ms.populate(target.Ring)
}

func (ms *MessageStore) GetCurrentTarget() (target ShardSector) {
    return ms.target
}

func (ms *MessageStore) Sync() (err error) {
    //should only have a single goroutine sync'ing at a time
    ms.syncMutex.Lock()
    if ms.syncInProgress {
        ms.syncMutex.Unlock()
        return nil
    }
    ms.syncInProgress = true
    ms.syncMutex.Unlock()
    defer func(ms *MessageStore) {
        ms.syncInProgress = false
    }(ms)
    
    lhc := ms.LHC
    lhc.Sync()
    newSync := lhc.lastRefresh
    
    ms.refreshSector(ms.sector, ms.lastRefresh)
    
    ms.lastRefresh = newSync
    
    ms.pruneExpired()
    
    return nil
}

func (ms *MessageStore) RefreshStatus() (status string) {
    status = "  "
    if ms.syncInProgress {
        status += "*  MS: refresh "
    } else {
        status += "   MS: refresh "
    }
    status += time.Unix(int64(ms.lastRefresh),0).UTC().Format("2006-01-02 15:04:05")
    status += fmt.Sprintf(" (-%04ds) h: %d\n", (uint32(time.Now().Unix())-ms.lastRefresh), ms.Count)
    status += ms.LHC.RefreshStatus()
    return status
}

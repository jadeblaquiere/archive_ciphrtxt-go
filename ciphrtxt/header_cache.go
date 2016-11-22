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
    "net/http"
    "io"
    "io/ioutil"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "errors"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/syndtr/goleveldb/leveldb/util"
    "os"
    "strconv"
    "sync"
    "time"
)

const apiStatus string = "api/v2/status"
const apiTime string = "api/v2/time"
const apiPeer string = "api/v2/peers"
const apiHeadersSince string = "api/v2/headers?since="
const apiMessagesDownload string = "api/v2/messages/"

const refreshMinDelay = 30

// {"pubkey": "030b5a7b432ec22920e20063cb16eb70dcb62dfef28d15eb19c1efeec35400b34b", "storage": {"max_file_size": 268435456, "capacity": 137438953472, "messages": 6252, "used": 17828492}}

type StatusStorageResponse struct {
    Capacity int `json:"capacity"`
    Headers int `json:"headers"`
    Maxfilesize int `json:"max_file_size"`
    Messages int `json:"messages"`
    Used int `json:"used"`
}

type StatusNetworkResponse struct {
    Host string `json:"host"`
    MSGPort int `json:"message_service_port"`
    TOKPort int `json:"token_service_port"`
}

type StatusResponse struct {
    Network StatusNetworkResponse `json:"network"`
    Pubkey string `json:"pubkey"`
    Sector  ShardSector `json:"sector"`
    Storage StatusStorageResponse `json:"storage"`
    Version string `json:"version"`
}

type TimeResponse struct {
    Time int `json:"time"`
}

type HeaderListResponse struct {
    Headers []string `json:"header_list"`
}

type MessageListResponse struct {
    Messages []string `json:"message_list"`
}

type MessageUploadResponse struct {
    Header string `json:"header"`
    Servertime uint32 `json:"servertime"`
}

type PeerItemResponse struct {
    Host string `json:"host"`
    Port uint16 `json:"port"`
}

type HeaderCache struct {
    host string
    port uint16
    baseurl string
    db *leveldb.DB
    syncMutex sync.Mutex
    syncInProgress bool
    status StatusResponse
    serverTime uint32
    lastRefreshServer uint32
    lastRefreshLocal uint32
    Count int
    NetworkErrors int
    PeerInfo []PeerItemResponse
}

// NOTE : if dbpath is empty ("") header cache will be in-memory only

func OpenHeaderCache(host string, port uint16, dbpath string) (hc *HeaderCache, err error) {
    hc = new(HeaderCache)
    hc.baseurl = fmt.Sprintf("http://%s:%d/", host, port)
    hc.host = host
    hc.port = port
    
    c := &http.Client{
        Timeout: time.Second * 10,
    }
    
    res, err := c.Get(hc.baseurl + apiStatus)
    if err != nil {
        //fmt.Printf("whoops1", err)
        return nil, err
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        //fmt.Printf("whoops2", err)
        return nil, err
    }
    
    err = json.Unmarshal(body, &hc.status)
    if err != nil {
        //fmt.Printf("failed to marshall result\n", err)
        return nil, err
    }
    
    if len(dbpath) == 0 {
        //fmt.Printf("whoops3", err)
        return nil, errors.New("refusing to open empty db path")
    }
    
    hc.db, err = leveldb.OpenFile(dbpath, nil)
    if err != nil {
        //fmt.Printf("whoops4", err)
        return nil, err
    }
    
    err = hc.recount()
    if err != nil {
        //fmt.Printf("whoops5", err)
        return nil, err
    }
    
    fmt.Printf("HeaderCache %s open, found %d message headers\n", hc.baseurl, hc.Count)
    return hc, nil
}

func (hc *HeaderCache) recount() (err error) {
    emptyMessage := "000000000000000000000000000000000000000000000000000000000000000000"
    expiredBegin, err := hex.DecodeString("E0" + "00000000" + emptyMessage)
    if err != nil {
        return err
    }
    expiredEnd, err := hex.DecodeString("E0" + "FFFFFFFF" + emptyMessage)
    if err != nil {
        return err
    }
    
    iter := hc.db.NewIterator(&util.Range{Start: expiredBegin,Limit: expiredEnd}, nil)

    count := int(0)
        
    for iter.Next() {
        count += 1
    }
    iter.Release()

    hc.Count = count
    
    return nil
}

func (hc *HeaderCache) Close() {
    if hc.db != nil {
        hc.db.Close()
        hc.db = nil
    }
}

type dbkeys struct {
    date []byte
    servertime []byte
    expire []byte
    I []byte
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

func serializeUint32(u uint32) []byte {
    buf := new(bytes.Buffer)
    binary.Write(buf, binary.BigEndian, u)
    su := make([]byte, 4)
    copy(su[:], buf.Bytes()[:])
    return su
}

func deserializeUint32(su []byte) uint32 {
    return binary.BigEndian.Uint32(su[:4])
}

func (hc *HeaderCache) Insert(h *RawMessageHeader) (insert bool, err error) {
    servertime := uint32(time.Now().Unix())
    dbk, err := h.dbKeys(servertime)
    if err != nil {
        fmt.Printf("HeaderCache.Insert: dbKeys returned error\n")
        return false, err
    }
    _, err = hc.db.Get(dbk.I, nil)
    if err == nil {
        return false, nil
    }
    //fmt.Printf("Insert len = %d, %d,", len([]byte(h.Serialize())[:]), len(serializeUint32(servertime)[:]))
    value := append([]byte(h.Serialize())[:], serializeUint32(servertime)[:]...)
    //fmt.Printf("%d\n", len(value))
    //value := h.Serialize()[:]
    batch := new(leveldb.Batch)
    batch.Put(dbk.date, value)
    batch.Put(dbk.servertime, value)
    batch.Put(dbk.expire, value)
    batch.Put(dbk.I, value)
    err = hc.db.Write(batch, nil)
    if err != nil {
        return false, err
    }
    hc.Count += 1
    return true, nil
}

func (hc *HeaderCache) Remove(h *RawMessageHeader) (err error) {
    value, err := hc.db.Get(h.I, nil)
    if err != nil {
        return err
    }
    servertime := deserializeUint32(value[MessageHeaderLengthB64V2:MessageHeaderLengthB64V2+4])
    dbk, err := h.dbKeys(servertime)
    if err != nil {
        return err
    }
    batch := new(leveldb.Batch)
    batch.Delete(dbk.date)
    batch.Delete(dbk.servertime)
    batch.Delete(dbk.expire)
    batch.Delete(dbk.I)
    hc.Count -= 1
    return hc.db.Write(batch, nil)
}

func (hc *HeaderCache) FindByI (I []byte) (h *RawMessageHeader, err error) {
    hc.Sync()

    value, err := hc.db.Get(I, nil)
    if err != nil {
        return nil, err
    }
    //fmt.Printf("FindbyI : length = %d\n", len(value))
    h = new(RawMessageHeader)
    if h.Deserialize(string(value[0:len(value)-4])) == nil {
        return nil, errors.New("retreived invalid header from database")
    }
    return h, nil
}

func (hc *HeaderCache) FindSince (tstamp uint32) (hdrs []RawMessageHeader, err error) {
    hc.Sync()

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
    
    iter := hc.db.NewIterator(&util.Range{Start: bin1, Limit: bin2}, nil)
    
    hdrs = make([]RawMessageHeader, 0)
    for iter.Next() {
        h := new(RawMessageHeader)
        value := iter.Value()
        if h.Deserialize(string(value[0:len(value)-4])) == nil {
            return nil, errors.New("error parsing message")
        }
        hdrs = append(hdrs, *h)
    }
    return hdrs, nil
}

func (hc *HeaderCache) FindExpiringAfter (tstamp uint32) (hdrs []RawMessageHeader, err error) {
    hc.Sync()

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
    
    iter := hc.db.NewIterator(&util.Range{Start: bin1, Limit: bin2}, nil)
    
    hdrs = make([]RawMessageHeader, 0)
    for iter.Next() {
        h := new(RawMessageHeader)
        value := iter.Value()
        if h.Deserialize(string(value[0:len(value)-4])) == nil {
            return nil, errors.New("error parsing message")
        }
        hdrs = append(hdrs, *h)
    }
    return hdrs, nil
}

func (hc *HeaderCache) getTime() (serverTime uint32, err error) {
    var tr TimeResponse

    c := &http.Client{
        Timeout: time.Second * 10,
    }
    
    res, err := c.Get(hc.baseurl + apiTime)
    if err != nil {
        hc.NetworkErrors += 1
        return 0, err
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        hc.NetworkErrors += 1
        return 0, err
    }
    
    hc.NetworkErrors = 0
    err = json.Unmarshal(body, &tr)
    if err != nil {
        return 0, err
    }
    
    hc.serverTime = uint32(tr.Time)
    return hc.serverTime, nil
}

func (hc *HeaderCache) getHeadersSince(since uint32) (mh []RawMessageHeader, err error) {
    c := &http.Client{
        Timeout: time.Second * 60,
    }
    
    res, err := c.Get(hc.baseurl + apiHeadersSince + strconv.FormatInt(int64(since),10))
    if err != nil {
        hc.NetworkErrors += 1
        return nil, err
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        hc.NetworkErrors += 1
        return nil, err
    }
    
    hc.NetworkErrors = 0
    s := new(HeaderListResponse)
    err = json.Unmarshal(body, &s)
    if err != nil {
        return nil, err
    }
    
    mh = make([]RawMessageHeader, 0)
    for _, hdr := range s.Headers {
        h := new(RawMessageHeader)
        if h.Deserialize(hdr) == nil {
            return nil, errors.New("error parsing message")
        }
        mh = append(mh, *h)
    }
    return mh, nil
}

func (hc *HeaderCache) pruneExpired() (err error) {
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

    iter := hc.db.NewIterator(&util.Range{Start: expiredBegin,Limit: expiredEnd}, nil)
    batch := new(leveldb.Batch)
    hdr := new(RawMessageHeader)
    
    delCount := int(0)
        
    for iter.Next() {
        value := iter.Value()
        if hdr.Deserialize(string(value[0:len(value)-4])) == nil {
            //return errors.New("unable to parse database value")
            fmt.Printf("HC(%s): unable to parse: %s\n", hc.baseurl, string(value[:MessageHeaderLengthB64V2]))
            continue
        }
        servertime := deserializeUint32(value[len(value)-4:len(value)])
        dbk, err := hdr.dbKeys(servertime)
        if err != nil {
            //return err
            fmt.Printf("HC(%s): failed to generate dbkeys\n", hc.baseurl)
            continue
        }
        batch.Delete(dbk.date)
        batch.Delete(dbk.servertime)
        batch.Delete(dbk.expire)
        batch.Delete(dbk.I)
        delCount += 1
    }
    iter.Release()
    
    err = hc.db.Write(batch, nil)
    if err == nil {
        hc.Count -= delCount
        //fmt.Printf("HC(%s) dropping %d message headers\n", hc.baseurl, delCount)
    }
    
    return err
}

func (hc *HeaderCache) Sync() (err error) {
    // if "fresh enough" (refreshMinDelay) then simply return
    now := uint32(time.Now().Unix())
    
    if (hc.lastRefreshLocal + refreshMinDelay) > now {
        return nil
    }
    
    //should only have a single goroutine sync'ing at a time
    hc.syncMutex.Lock()
    if hc.syncInProgress {
        hc.syncMutex.Unlock()
        return nil
    }
    hc.syncInProgress = true
    hc.syncMutex.Unlock()
    defer func(hc *HeaderCache) {
        hc.syncInProgress = false
    }(hc)
    
    //fmt.Printf("HeaderCache.Sync: %s sync @ now, last, next = %d, %d, %d\n", hc.baseurl, now, hc.lastRefreshLocal, (hc.lastRefreshLocal + refreshMinDelay))
    
    serverTime, err := hc.getTime()
    if err != nil {
        return err
    }
    
    err = hc.pruneExpired()
    if err != nil {
        return err
    }
    
    mhdrs, err := hc.getHeadersSince(hc.lastRefreshServer)
    if err != nil {
        return err
    }
    
    insCount := int(0)

    for _, mh := range mhdrs {
        insert, err := hc.Insert(&mh)
        if err != nil {
            fmt.Printf("hc.Insert failed: %s\n", err)
            continue
        }
        if insert {
            insCount += 1
        }
    }

    hc.lastRefreshServer = serverTime
    hc.lastRefreshLocal = now

    //fmt.Printf("insert %d message headers\n", insCount)

    return nil
}

func (hc *HeaderCache) tryDownloadMessage(I []byte, recvpath string) (m *MessageFile, err error) {
    c := &http.Client{
        Timeout: time.Second * 60,
    }

    //fmt.Printf("try download %s\n", hc.baseurl + apiMessagesDownload + hex.EncodeToString(I))
    res, err := c.Get(hc.baseurl + apiMessagesDownload + hex.EncodeToString(I))
    if err != nil {
        hc.NetworkErrors += 1
        return nil, err
    }

    hc.NetworkErrors = 0
    f, err := os.Create(recvpath)
    if err != nil {
        return nil, err
    }

    _, err = io.Copy(f, res.Body)
    if err != nil {
        return nil, err
    }
    
    f.Close()

    m = Ingest(recvpath)
    if m == nil {
        os.Remove(recvpath)
        return nil, fmt.Errorf("Error receiving file to %s", recvpath)
    }
    
    return m, nil
}

func (hc *HeaderCache) getPeerInfo() (err error) {
    var plr []PeerItemResponse

    c := &http.Client{
        Timeout: time.Second * 10,
    }
    
    res, err := c.Get(hc.baseurl + apiPeer)
    if err != nil {
        hc.NetworkErrors += 1
        return err
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        hc.NetworkErrors += 1
        return err
    }
    
    hc.NetworkErrors = 0
    err = json.Unmarshal(body, &plr)
    if err != nil {
        return err
    }
    
    //fmt.Printf("Host %s returned %d peers:\n", hc.baseurl, len(plr))
    //for _, p := range plr {
    //    fmt.Printf("peer host = %s, port = %d\n",p.Host, p.Port)
    //}
    
    hc.PeerInfo = plr
    return nil
}

func (hc *HeaderCache) postPeerInfo(host string, port uint16) (err error) {
    var pir PeerItemResponse
    
    pir.Host = host
    pir.Port = port
    
    body, err := json.Marshal(&pir)
    if err != nil {
        return err
    }
    //fmt.Printf("body for peer info post:\n%s\n", string(body))

    c := &http.Client{
        Timeout: time.Second * 10,
    }
    
    //fmt.Printf("POSTing message to : %s\n", hc.baseurl + apiPeer)
    res, err := c.Post(hc.baseurl + apiPeer, "application/json", bytes.NewBuffer(body))
    if err != nil {
        hc.NetworkErrors += 1
        return err
    }
    
    body, err = ioutil.ReadAll(res.Body)
    if err != nil {
        hc.NetworkErrors += 1
        return err
    }
    
    if res.StatusCode != 200 {
        fmt.Printf("HC:postPeerInfo POST Complete, received error response\n")
        fmt.Printf("response status = %d\n", res.StatusCode)
        fmt.Printf("response status text = %s\n", res.Status)
        fmt.Printf("response header fields:\n")
        for k, v := range res.Header {
            fmt.Println("key:", k, "value:", v)
        }
        fmt.Printf("response: \n%s\n", body)
    }
    
    return nil
}

func (hc *HeaderCache) RefreshStatus() (status string) {
    status = "  "
    if hc.syncInProgress {
        status += "*  HC:  refresh "
    } else {
        status += "   HC:  refresh "
    }
    status += time.Unix(int64(hc.lastRefreshLocal),0).UTC().Format("2006-01-02 15:04:05")
    status += fmt.Sprintf(" (-%04ds) ", (uint32(time.Now().Unix())-hc.lastRefreshLocal))
    status += fmt.Sprintf(" skew l-r: %d    ", (int(hc.lastRefreshLocal)-int(hc.lastRefreshServer)))
    status += fmt.Sprintf("h: %d ",hc.Count)
    status += hc.baseurl + "\n"
    return status
}

type PeerJSON struct {
    Host string `json:"host"`
    Port uint16 `json:"port"`
    URL string `json:"url"`
    Headers int `json:"headers"`
    Messages int `json:"messages"`
    Start int `json:"start"`
    Ring int `json:"ring"`
}

func (hc *HeaderCache) GetPeerStatsJSON() (stats *PeerJSON) {
    pi := new(PeerJSON)
    pi.Host = hc.host
    pi.Port = hc.port
    pi.URL = "http://" + hc.host + ":" + strconv.Itoa(int(hc.port)) + "/"
    pi.Headers = hc.status.Storage.Headers
    pi.Messages = hc.status.Storage.Messages
    pi.Start = hc.status.Sector.Start
    pi.Ring = int(hc.status.Sector.Ring)
    return pi
}

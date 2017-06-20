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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	cwebsocket "github.com/jadeblaquiere/websocket-client"
	"github.com/kataras/iris/websocket"
)

const apiStatus string = "api/v2/status"
const apiTime string = "api/v2/time"
const apiPeer string = "api/v2/peers"
const apiHeadersSince string = "api/v2/headers?since="
const apiMessagesDownload string = "api/v2/messages/"
const apiDownloadNoRecurse string = "?recurse=false"
const apiWebsocketEndpoint string = "wsapi/v2/ws"
const apiWebsocketPongInterval = 60 * time.Second
const apiWebsocketPingInterval = (9 * apiWebsocketPongInterval) / 10
const apiWebsocketWriteWait = 60 * time.Second
const apiWebsocketReadWait = 60 * time.Second

const refreshMinDelay = 30

// {"pubkey": "030b5a7b432ec22920e20063cb16eb70dcb62dfef28d15eb19c1efeec35400b34b", "storage": {"max_file_size": 268435456, "capacity": 137438953472, "messages": 6252, "used": 17828492}}

type StatusStorageResponse struct {
	Capacity    int `json:"capacity"`
	Headers     int `json:"headers"`
	Maxfilesize int `json:"max_file_size"`
	Messages    int `json:"messages"`
	Used        int `json:"used"`
}

type StatusNetworkResponse struct {
	Host    string `json:"host"`
	MSGPort int    `json:"message_service_port"`
	TOKPort int    `json:"token_service_port"`
}

type StatusResponse struct {
	Network StatusNetworkResponse `json:"network"`
	Pubkey  string                `json:"pubkey"`
	Sector  ShardSector           `json:"sector"`
	Storage StatusStorageResponse `json:"storage"`
	Version string                `json:"version"`
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
	Header     string `json:"header"`
	Servertime uint32 `json:"servertime"`
}

type PeerItemResponse struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

type TimeRequest struct {
	RequestType uint32 `json:"request_type"`
}

type HeaderCache struct {
	host              string
	port              uint16
	baseurl           string
	wsurl             string
	db                *leveldb.DB
	syncMutex         sync.Mutex
	syncInProgress    bool
	status            StatusResponse
	serverTime        uint32
	lastRefreshServer uint32
	lastRefreshLocal  uint32
	Count             int
	NetworkErrors     int
	PeerInfo          []PeerItemResponse
	wsclient          cwebsocket.ClientConnection
}

// NOTE : if dbpath is empty ("") header cache will be in-memory only

func OpenHeaderCache(host string, port uint16, dbpath string) (hc *HeaderCache, err error) {
	hc = new(HeaderCache)
	hc.baseurl = fmt.Sprintf("http://%s:%d/", host, port)
	hc.wsurl = fmt.Sprintf("ws://%s:%d/", host, port)
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

	if hc.recoverCheckpoint() != nil {
		err = hc.recount()
		if err != nil {
			//fmt.Printf("whoops5", err)
			return nil, err
		}
	} else {
		fmt.Printf("HeaderCache recovered checkpoint @ tstamp %d\n", hc.serverTime)
	}

	dialer := new(cwebsocket.WSDialer)

	// fmt.Println("Dialing : ", string(hc.wsurl+apiWebsocketEndpoint))

	client, _, err := dialer.Dial(string(hc.wsurl+apiWebsocketEndpoint), nil, websocket.Config{
		ReadTimeout:     60 * time.Second,
		WriteTimeout:    60 * time.Second,
		PingPeriod:      9 * 6 * time.Second,
		PongTimeout:     60 * time.Second,
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		BinaryMessages:  true,
	})
	if err != nil {
		fmt.Printf("Unable to connect to websocket endpoint %s, proceeding by polling only\n", hc.wsurl+apiWebsocketEndpoint)
	} else {
		hc.SetupWSHandler(client)
	}

	fmt.Printf("HeaderCache %s open, found %d message headers\n", hc.baseurl, hc.Count)
	return hc, nil
}

func (hc *HeaderCache) SetupWSHandler(client cwebsocket.ClientConnection) {
	hc.wsclient = client
	client.OnDisconnect(hc.HandleWSDisconnect)
	client.On("time_response", hc.HandleWSTimeResponse)
	client.On("status_response", hc.HandleWSStatusResponse)
}

func (hc *HeaderCache) HandleWSTimeResponse(message int) {
	hc.NetworkErrors = 0
	hc.UpdateTime(uint32(message))
}

func (hc *HeaderCache) HandleWSStatusResponse(message StatusResponse) {
	hc.NetworkErrors = 0
	hc.status = message
}

func (hc *HeaderCache) HandleWSDisconnect() {
	hc.wsclient = nil
}

func (hc *HeaderCache) WebsocketWatchdog() {
	watchdog := time.NewTimer(refreshMinDelay * time.Second)
	for {
		select {
		case <-watchdog.C:
			hc.NetworkErrors += 1
			hc.wsclient.Emit("time_request", "")
		}
	}
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

	iter := hc.db.NewIterator(&util.Range{Start: expiredBegin, Limit: expiredEnd}, nil)

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
	date       []byte
	servertime []byte
	expire     []byte
	I          []byte
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

func (hc *HeaderCache) checkpoint() (err error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, hc.serverTime)
	binary.Write(buf, binary.BigEndian, hc.lastRefreshServer)
	binary.Write(buf, binary.BigEndian, hc.lastRefreshLocal)
	binary.Write(buf, binary.BigEndian, uint64(hc.Count))
	value := buf.Bytes()[:]
	key := []byte("\000\000\000\000")
	return hc.db.Put(key, value, nil)
}

func (hc *HeaderCache) recoverCheckpoint() (err error) {
	key := []byte("\000\000\000\000")
	value, err := hc.db.Get(key, nil)
	if err != nil {
		return err
	}

	if len(value) != 20 {
		return fmt.Errorf("checkpoint value length mismatch")
	}
	hc.serverTime = binary.BigEndian.Uint32(value[0:4])
	hc.lastRefreshServer = binary.BigEndian.Uint32(value[4:8])
	hc.lastRefreshLocal = binary.BigEndian.Uint32(value[8:12])
	hc.Count = int(binary.BigEndian.Uint64(value[12:20]))
	return nil
}

func (hc *HeaderCache) Insert(h MessageHeader) (insert bool, err error) {
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

func (hc *HeaderCache) Remove(h MessageHeader) (err error) {
	value, err := hc.db.Get(h.IKey(), nil)
	if err != nil {
		return err
	}
	servertime := deserializeUint32(value[MessageHeaderLengthB64V2 : MessageHeaderLengthB64V2+4])
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

func (hc *HeaderCache) FindByI(I []byte) (h MessageHeader, err error) {
	hc.Sync()

	value, err := hc.db.Get(I, nil)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("FindbyI : length = %d\n", len(value))
	h = new(RawMessageHeader)
	if h.Deserialize(string(value[0:len(value)-4])) != nil {
		return nil, errors.New("retreived invalid header from database")
	}
	return h, nil
}

func (hc *HeaderCache) FindSince(tstamp uint32) (hdrs []RawMessageHeader, err error) {
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
		if h.Deserialize(string(value[0:len(value)-4])) != nil {
			return nil, errors.New("error parsing message")
		}
		hdrs = append(hdrs, *h)
	}
	return hdrs, nil
}

func (hc *HeaderCache) FindExpiringAfter(tstamp uint32) (hdrs []RawMessageHeader, err error) {
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
		if h.Deserialize(string(value[0:len(value)-4])) != nil {
			return nil, errors.New("error parsing message")
		}
		hdrs = append(hdrs, *h)
	}
	return hdrs, nil
}

func (hc *HeaderCache) UpdateTime(serverTime uint32) (err error) {
	// don't let time go backwards
	if serverTime > hc.serverTime {
		hc.serverTime = serverTime
		return nil
	}
	return fmt.Errorf("Attempt to update time backwards")
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

	err = json.Unmarshal(body, &tr)
	if err != nil {
		hc.NetworkErrors += 1
		return 0, err
	}

	hc.NetworkErrors = 0
	hc.serverTime = uint32(tr.Time)
	return hc.serverTime, nil
}

func (hc *HeaderCache) getHeadersSince(since uint32) (mh []RawMessageHeader, err error) {
	c := &http.Client{
		Timeout: time.Second * 60,
	}

	res, err := c.Get(hc.baseurl + apiHeadersSince + strconv.FormatInt(int64(since), 10))
	if err != nil {
		hc.NetworkErrors += 1
		return nil, err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		hc.NetworkErrors += 1
		return nil, err
	}

	s := new(HeaderListResponse)
	err = json.Unmarshal(body, &s)
	if err != nil {
		return nil, err
	}

	hc.NetworkErrors = 0
	mh = make([]RawMessageHeader, 0)
	for _, hdr := range s.Headers {
		h := new(RawMessageHeader)
		if h.Deserialize(hdr) != nil {
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
	now := strconv.FormatUint(uint64(time.Now().Unix()), 16)
	expiredEnd, err := hex.DecodeString("E0" + now + emptyMessage)
	if err != nil {
		return err
	}

	iter := hc.db.NewIterator(&util.Range{Start: expiredBegin, Limit: expiredEnd}, nil)
	batch := new(leveldb.Batch)
	hdr := new(RawMessageHeader)

	delCount := int(0)

	for iter.Next() {
		value := iter.Value()
		if hdr.Deserialize(string(value[0:len(value)-4])) != nil {
			//return errors.New("unable to parse database value")
			fmt.Printf("HC(%s): unable to parse: %s\n", hc.baseurl, string(value[:MessageHeaderLengthB64V2]))
			continue
		}
		servertime := deserializeUint32(value[len(value)-4 : len(value)])
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
	if hc.wsclient != nil {
		return hc.syncAsync()
	}
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
		hc.syncMutex.Lock()
		hc.syncInProgress = false
		hc.syncMutex.Unlock()
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

	hc.checkpoint()

	hc.lastRefreshServer = serverTime
	hc.lastRefreshLocal = now

	//fmt.Printf("insert %d message headers\n", insCount)

	return nil
}

func (hc *HeaderCache) syncAsync() (err error) {
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
		hc.syncMutex.Lock()
		hc.syncInProgress = false
		hc.syncMutex.Unlock()
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

	hc.checkpoint()

	hc.lastRefreshServer = serverTime
	hc.lastRefreshLocal = now

	//fmt.Printf("insert %d message headers\n", insCount)

	return nil
}

func (hc *HeaderCache) tryDownloadMessage(I []byte, recvpath string) (m *MessageFile, err error) {
	c := &http.Client{
		Timeout: time.Second * 60,
	}

	// fmt.Printf("try download %s\n", hc.baseurl + apiMessagesDownload + hex.EncodeToString(I) + apiDownloadNoRecurse)
	res, err := c.Get(hc.baseurl + apiMessagesDownload + hex.EncodeToString(I) + apiDownloadNoRecurse)
	if err != nil {
		hc.NetworkErrors += 1
		return nil, err
	}

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

	hc.NetworkErrors = 0
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

	err = json.Unmarshal(body, &plr)
	if err != nil {
		return err
	}

	//fmt.Printf("Host %s returned %d peers:\n", hc.baseurl, len(plr))
	//for _, p := range plr {
	//    fmt.Printf("peer host = %s, port = %d\n",p.Host, p.Port)
	//}

	hc.NetworkErrors = 0
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
	res, err := c.Post(hc.baseurl+apiPeer, "application/json", bytes.NewBuffer(body))
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
	status += time.Unix(int64(hc.lastRefreshLocal), 0).UTC().Format("2006-01-02 15:04:05")
	status += fmt.Sprintf(" (-%04ds) ", (uint32(time.Now().Unix()) - hc.lastRefreshLocal))
	status += fmt.Sprintf(" skew l-r: %d    ", (int(hc.lastRefreshLocal) - int(hc.lastRefreshServer)))
	status += fmt.Sprintf("h: %d ", hc.Count)
	status += hc.baseurl + "\n"
	return status
}

type PeerJSON struct {
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	URL      string `json:"url"`
	Headers  int    `json:"headers"`
	Messages int    `json:"messages"`
	Start    int    `json:"start"`
	Ring     int    `json:"ring"`
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

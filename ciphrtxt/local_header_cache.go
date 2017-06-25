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
	"errors"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"math/rand"
	"strconv"
	"sync"
	"time"

	cwebsocket "github.com/jadeblaquiere/websocket-client"
	iwebsocket "github.com/kataras/iris/websocket"
)

const lhcRefreshMinDelay = 30
const lhcPeerConsecutiveErrorMax = 5
const lhcPeerInfoMinDelay = 300

type peerCache struct {
	HC              *HeaderCache
	lastRefresh     uint32
	lastGetPeers    uint32
	wshandler       WSProtocolHandler
	watchdogExpired bool
}

func (pc *peerCache) Disconnect() {
	pc.watchdogExpired = true
}

type peerCandidate struct {
	host      string
	port      uint16
	wshandler WSProtocolHandler
}

var defaultSeedPeers []*peerCandidate = []*peerCandidate{
	&peerCandidate{"indigo.ciphrtxt.com", 7754, nil},
	&peerCandidate{"violet.ciphrtxt.com", 7754, nil},
}

type LocalHeaderCache struct {
	basepath                string
	db                      *leveldb.DB
	syncMutex               sync.Mutex
	syncInProgress          bool
	serverTime              uint32
	lastRefresh             uint32
	Count                   int
	Peers                   []*peerCache
	peerCandidateMutex      sync.Mutex
	peerCandidates          []*peerCandidate
	discoverPeersMutex      sync.Mutex
	discoverPeersInProgress bool
	lastPeerSync            uint32
	ms                      *MessageStore
	ExternalHost            string
	ExternalPort            int
	ExtTokenPort            int
	PubKey                  string
}

func OpenLocalHeaderCache(filepath string) (lhc *LocalHeaderCache, err error) {
	lhc = new(LocalHeaderCache)
	lhc.basepath = filepath

	dbpath := filepath + "/localdb"

	if len(dbpath) == 0 {
		return nil, errors.New("refusing to open empty db path")
	}

	lhc.db, err = leveldb.OpenFile(dbpath, nil)
	if err != nil {
		return nil, err
	}

	err = lhc.recount()
	if err != nil {
		return nil, err
	}

	fmt.Printf("LocalHeaderCache open, found %d message headers\n", lhc.Count)
	return lhc, nil
}

func (lhc *LocalHeaderCache) recount() (err error) {
	emptyMessage := "000000000000000000000000000000000000000000000000000000000000000000"

	expiredBegin, err := hex.DecodeString("E0" + "00000000" + emptyMessage)
	if err != nil {
		return err
	}

	expiredEnd, err := hex.DecodeString("E0" + "FFFFFFFF" + emptyMessage)
	if err != nil {
		return err
	}

	iter := lhc.db.NewIterator(&util.Range{Start: expiredBegin, Limit: expiredEnd}, nil)

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
		if p.HC != nil {
			p.HC.Close()
			p.HC = nil
		}
	}

	if lhc.db != nil {
		lhc.db.Close()
		lhc.db = nil
	}
}

func (lhc *LocalHeaderCache) ConnectWSPeer(con iwebsocket.Connection) {
	pc := new(peerCandidate)
	pc.wshandler = NewWSProtocolHandler(con, lhc, nil)
	con.Emit("request-status", int(0))
	for tries := 30; tries > 0; tries-- {
		status := pc.wshandler.Status()
		if status != nil {
			pc.host = status.Network.Host
			pc.port = uint16(status.Network.MSGPort)
			fmt.Printf("LHC: submitting incoming peer %s:%d for consideration\n", pc.host, pc.port)
			lhc.peerCandidateMutex.Lock()
			defer lhc.peerCandidateMutex.Unlock()
			lhc.peerCandidates = append(lhc.peerCandidates, pc)
			return
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Printf("LHC: failed to get status from ws-connected peer, disconnecting...\n")
	pc.wshandler.Disconnect()
}

func (lhc *LocalHeaderCache) Insert(h MessageHeader) (insert bool, err error) {
	servertime := uint32(time.Now().Unix())

	dbk, err := h.dbKeys(servertime)
	if err != nil {
		return false, err
	}

	_, err = lhc.db.Get(dbk.I, nil)
	if err == nil {
		return false, nil
	}

	value := append([]byte(h.Serialize())[:], serializeUint32(servertime)[:]...)

	batch := new(leveldb.Batch)
	batch.Put(dbk.date, value)
	batch.Put(dbk.servertime, value)
	batch.Put(dbk.expire, value)
	batch.Put(dbk.I, value)

	err = lhc.db.Write(batch, nil)
	if err != nil {
		return false, err
	}

	notifyPeers := lhc.Peers[:]
	for _, peer := range notifyPeers {
		if peer.wshandler != nil {
			rh, _ := peer.HC.FindByI(dbk.I)
			if rh == nil {
				peer.wshandler.TxHeader(h)
			}
		}
	}

	lhc.Count += 1
	return true, nil
}

func (lhc *LocalHeaderCache) Remove(h MessageHeader) (err error) {
	value, err := lhc.db.Get(h.IKey(), nil)
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
	lhc.Count -= 1
	return lhc.db.Write(batch, nil)
}

func (lhc *LocalHeaderCache) FindByI(I []byte) (h *RawMessageHeader, err error) {
	lhc.Sync()

	value, err := lhc.db.Get(I, nil)
	if err != nil {
		return nil, err
	}
	h = new(RawMessageHeader)
	if h.Deserialize(string(value)) != nil {
		return nil, errors.New("retreived invalid header from database")
	}
	return h, nil
}

func (lhc *LocalHeaderCache) FindSince(tstamp uint32) (hdrs []RawMessageHeader, err error) {
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
		if h.Deserialize(string(iter.Value())) != nil {
			return nil, errors.New("error parsing message header")
		}
		hdrs = append(hdrs, *h)
	}
	return hdrs, nil
}

func (lhc *LocalHeaderCache) findSector(seg ShardSector) (hdrs []RawMessageHeader, err error) {
	var tag1, tag2, tag3, tag4 string
	var bin1, bin2, bin3, bin4 []byte

	start := seg.Start
	ring := seg.Ring

	lhc.Sync()

	//fmt.Printf("LocalHeaderCache.findSector %04x, %d\n", start, ring)

	if (start < 0x0200) || (start > 0x03ff) {
		return nil, fmt.Errorf("LocalHeaderCache.findSector start value out of range")
	}

	if (ring < 0) || (ring > 9) {
		return nil, fmt.Errorf("LocalHeaderCache.findSector ring value out of range")
	}

	ringsz := 512 >> ring
	end := start + ringsz

	emptyMessage := "00000000000000000000000000000000000000000000000000000000000000"
	tag1 = fmt.Sprintf("%04X%s", start, emptyMessage)

	if end > 0x400 {
		tag2 = fmt.Sprintf("0400%s", emptyMessage)
		tag3 = fmt.Sprintf("0000%s", emptyMessage)
		tag4 = fmt.Sprintf("%04X%s", ((end & 0x03FF) | (0x0200)), emptyMessage)

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
		if h.Deserialize(string(iter.Value())) != nil {
			return nil, errors.New("error parsing message")
		}
		hdrs = append(hdrs, *h)
	}

	if end > 0x400 {
		iter := lhc.db.NewIterator(&util.Range{Start: bin3, Limit: bin4}, nil)

		for iter.Next() {
			h := new(RawMessageHeader)
			if h.Deserialize(string(iter.Value())) != nil {
				return nil, errors.New("error parsing message header")
			}
			hdrs = append(hdrs, *h)
		}
	}

	//fmt.Printf("found %d headers\n", len(hdrs))
	return hdrs, nil
}

func (lhc *LocalHeaderCache) FindExpiringAfter(tstamp uint32) (hdrs []RawMessageHeader, err error) {
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
		if h.Deserialize(string(iter.Value())) != nil {
			return nil, errors.New("error parsing message header")
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
	now := strconv.FormatUint(uint64(time.Now().Unix()), 16)
	expiredEnd, err := hex.DecodeString("E0" + now + emptyMessage)
	if err != nil {
		return err
	}

	iter := lhc.db.NewIterator(&util.Range{Start: expiredBegin, Limit: expiredEnd}, nil)
	batch := new(leveldb.Batch)
	hdr := new(RawMessageHeader)

	delCount := int(0)

	for iter.Next() {
		value := iter.Value()
		if hdr.Deserialize(string(value[0:len(value)-4])) != nil {
			//return errors.New("unable to parse database value")
			fmt.Printf("LHC: unable to parse: %s\n", string(value[:MessageHeaderLengthB64V2]))
			continue
		}
		servertime := deserializeUint32(value[len(value)-4 : len(value)])
		dbk, err := hdr.dbKeys(servertime)
		if err != nil {
			//return err
			fmt.Printf("LHC: failed to generate dbkeys\n")
			continue
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
		//fmt.Printf("LocalHeaderCache: dropping %d message headers\n", delCount)
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
	if len(candidates) == 0 {
		candidates = make([]*peerCandidate, len(defaultSeedPeers))
		copy(candidates, defaultSeedPeers)
	}
	lhc.peerCandidates = make([]*peerCandidate, len(defaultSeedPeers))
	copy(lhc.peerCandidates, defaultSeedPeers)
	lhc.peerCandidateMutex.Unlock()

	for _, pc := range candidates {
		if lhc.addPeer(pc) != nil {
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
	//for i := 0 ; i < nPeers ; i++ {
	//    p := lhc.Peers[ordinal[i]]
	//    fmt.Printf("%d : %s:%d\n", ordinal[i], p.HC.host, p.HC.port)
	//}
	//fmt.Printf("\n")
	for i := 0; i < nPeers; i++ {
		p := lhc.Peers[ordinal[i]]

		p.HC.Sync()

		lastRefreshPeer := p.HC.lastRefreshServer

		if lastRefreshPeer > p.lastRefresh {
			mhdrs, err := p.HC.FindSince(p.lastRefresh)
			if err != nil {
				return err
			}

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

			//fmt.Printf("LocalHeaderCache: inserted %d message headers\n", insCount)
		}
	}

	newPeers := make([]*peerCache, 0, len(lhc.Peers))
	for _, p := range lhc.Peers {
		if p.HC.NetworkErrors < lhcPeerConsecutiveErrorMax {
			if p.watchdogExpired == false {
				newPeers = append(newPeers, p)
			} else {
				fmt.Printf("LocalHeaderCache: dropping peer %s (websocket connection disconnected)\n", p.HC.baseurl)
				p.HC.Close()
			}
		} else {
			fmt.Printf("LocalHeaderCache: dropping peer %s (error count too high)\n", p.HC.baseurl)
			p.HC.Close()
		}
	}

	lhc.Peers = newPeers

	lhc.lastRefresh = now

	lhc.Count += insCount

	//fmt.Printf("LocalHeaderCache: insert %d message headers\n", insCount)

	//fmt.Printf("LocalHeaderCache: %d active message headers\n", lhc.Count)

	return nil
}

func (lhc *LocalHeaderCache) AddPeer(host string, port uint16) {
	lhc.peerCandidateMutex.Lock()
	defer lhc.peerCandidateMutex.Unlock()

	pc := new(peerCandidate)
	pc.host = host
	pc.port = port

	lhc.peerCandidates = append(lhc.peerCandidates, pc)
}

func (lhc *LocalHeaderCache) addPeer(pcan *peerCandidate) (err error) {
	host := pcan.host
	port := pcan.port
	if (host == lhc.ExternalHost) && (port == uint16(lhc.ExternalPort)) {
		return fmt.Errorf("LHC.addPeer : refusing to connect to self")
	}
	for _, p := range lhc.Peers {
		if (p.HC.host == host) && (p.HC.port == port) {
			// fmt.Printf("addPeer: %s:%d already connected\n", host, port)
			if p.wshandler == nil {
				if pcan.wshandler != nil {
					fmt.Printf("LHC.addPeer: %s:%d adoping websocket connection", host, port)
					p.wshandler = pcan.wshandler
					p.wshandler.OnDisconnect(p.Disconnect)
					pcan.wshandler = nil
				} else {
					if pcan.wshandler != nil {
						fmt.Printf("LHC.addPeer: %s:%d dropping duplicate websocket connection", host, port)
						pcan.wshandler.Disconnect()
					}
				}
			} else {
				if pcan.wshandler != nil {
					fmt.Printf("LHC.addPeer: dropping incoming connected duplicate %s:%d\n", host, port)
					pcan.wshandler.Disconnect()
				}
			}
			return fmt.Errorf("addPeer: %s:%d already connected", host, port)
		}
	}

	dbpath := lhc.basepath + "/remote/" + host + "_" + strconv.Itoa(int(port)) + "/hdb"

	pc := new(peerCache)

	rhc, err := OpenHeaderCache(host, port, dbpath)
	if err != nil {
		fmt.Printf("addPeer: %s:%d open header cache failed\n", host, port)
		return err
	}

	err = rhc.Sync()
	if err != nil {
		fmt.Printf("addPeer: %s:%d sync error\n", host, port)
		return err
	}

	lastRefresh := rhc.lastRefreshServer

	mhdrs, err := rhc.FindSince(0)
	if err != nil {
		fmt.Printf("addPeer: %s:%d Error finding all headers\n", host, port)
		return err
	}

	pc.HC = rhc
	pc.lastRefresh = lastRefresh

	pc.wshandler = pcan.wshandler
	pc.watchdogExpired = false

	if pc.wshandler == nil {
		dialer := new(cwebsocket.WSDialer)

		fmt.Println("Dialing : ", string(rhc.wsurl+apiWebsocketEndpoint))

		client, _, err := dialer.Dial(string(rhc.wsurl+apiWebsocketEndpoint), nil, iwebsocket.Config{
			ReadTimeout:     60 * time.Second,
			WriteTimeout:    60 * time.Second,
			PingPeriod:      9 * 6 * time.Second,
			PongTimeout:     60 * time.Second,
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			BinaryMessages:  true,
		})
		if err != nil {
			fmt.Printf("Unable to connect to websocket endpoint %s, proceeding by polling only\n", rhc.wsurl+apiWebsocketEndpoint)
		} else {
			pc.wshandler = NewWSProtocolHandler(client, lhc, rhc)
			pc.wshandler.OnDisconnect(pc.Disconnect)
		}
	} else {
		fmt.Println("Not Dialing, already connected", string(rhc.wsurl+apiWebsocketEndpoint))
	}

	lhc.Peers = append(lhc.Peers, pc)

	go func(lhc *LocalHeaderCache, mhdrs []RawMessageHeader) {
		for _, mh := range mhdrs {
			_, err := lhc.Insert(&mh)
			if err != nil {
				continue
			}
			//if insert {
			//    insCount += 1
			//}
		}
	}(lhc, mhdrs)

	//fmt.Printf("LocalHeaderCache: inserted %d message headers\n", insCount)

	//lhc.recount()

	//fmt.Printf("LocalHeaderCache: %d active message headers\n", lhc.Count)

	return nil
}

func (lhc *LocalHeaderCache) ListPeers() (plr []PeerItemResponse) {
	plr = make([]PeerItemResponse, 0)
	for _, p := range lhc.Peers {
		pir := new(PeerItemResponse)
		pir.Host = p.HC.host
		pir.Port = p.HC.port
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
			if p.HC.getPeerInfo() == nil {
				p.lastGetPeers = now

				//fmt.Printf("Updating peer info for HC : %s\n", p.HC.baseurl)

				needsLocal := true
				for _, remote := range p.HC.PeerInfo {
					//fmt.Printf("Peer %s has peer %s:%d\n", p.HC.baseurl, remote.Host, remote.Port)
					remoteNew := true
					for _, local := range lhc.Peers {
						if (local.HC.host == remote.Host) && (local.HC.port == remote.Port) {
							//fmt.Printf("peer %s:%d already in my peer list\n", remote.Host, remote.Port)
							remoteNew = false
							break
						}
					}
					if (remote.Host == exthost) && (remote.Port == extport) {
						//fmt.Printf("remote host is me!\n")
						needsLocal = false
					} else {
						if remoteNew {
							//fmt.Printf("trying to add host")
							lhc.AddPeer(remote.Host, remote.Port)
							//if err != nil {
							//    fmt.Printf("error adding peer: %s\n", err)
							//}
						}
					}
				}
				if needsLocal {
					//fmt.Printf("Peer %s doesn't have me in the list, pushing\n", p.HC.baseurl)
					err = p.HC.postPeerInfo(exthost, extport)
					//if err != nil {
					//    fmt.Printf("unable to push myself as peer to %s\n", p.HC.baseurl)
					//}
				}
			}
		}
	}

	lhc.lastPeerSync = now

	return nil
}

func (lhc *LocalHeaderCache) RefreshStatus() (status string) {
	status = "  "
	if lhc.syncInProgress {
		status += "*  LH:  refresh "
	} else {
		status += "   LH:  refresh "
	}
	status += time.Unix(int64(lhc.lastRefresh), 0).UTC().Format("2006-01-02 15:04:05")
	status += fmt.Sprintf(" (-%04ds) ", (uint32(time.Now().Unix()) - lhc.lastRefresh))
	status += fmt.Sprintf("h: %d ", lhc.Count)
	status += "\n  "
	if lhc.discoverPeersInProgress {
		status += "*  LH: discover "
	} else {
		status += "   LH: discover "
	}
	status += time.Unix(int64(lhc.lastPeerSync), 0).UTC().Format("2006-01-02 15:04:05")
	status += fmt.Sprintf(" (-%04ds)\n", (uint32(time.Now().Unix()) - lhc.lastPeerSync))
	for _, p := range lhc.Peers {
		status += p.HC.RefreshStatus()
	}
	status += fmt.Sprintf("\nWebsocket Peers:\n")
	for _, wsh := range wsHandlerList {
		if wsh.remote == nil {
			status += fmt.Sprintf("Pending WS peer %s:%d (inbound)\n", wsh.tmpStatus.Network.Host, wsh.tmpStatus.Network.MSGPort)
		} else {
			status += fmt.Sprintf("Connected WS peer %s:%d ", wsh.remote.host, wsh.remote.port)
			if wsh.inbound {
				status += fmt.Sprintf("(inbound)\n")
			} else {
				status += fmt.Sprintf("(outbound)\n")
			}
		}
	}
	return status
}

func (lhc *LocalHeaderCache) Status() (status *StatusResponse) {
	if lhc.ms != nil {
		return lhc.ms.Status()
	}
	r_storage := StatusStorageResponse{
		Headers:     lhc.Count,
		Messages:    0,
		Maxfilesize: (8 * 1024 * 1024),
		Capacity:    (256 * 1024 * 1024 * 1024),
		Used:        0,
	}

	r_network := StatusNetworkResponse{
		lhc.ExternalHost,
		lhc.ExternalPort,
		lhc.ExtTokenPort,
	}

	r_sector := ShardSector{
		Start: 0,
		Ring:  10,
	}

	r_status := StatusResponse{
		Network: r_network,
		Pubkey:  lhc.PubKey,
		Storage: r_storage,
		Sector:  r_sector,
		Version: "0.2.0",
	}
	return &r_status
}

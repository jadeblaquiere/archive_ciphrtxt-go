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
	// "bytes"
	"encoding/json"
	"fmt"
	"time"

	cwebsocket "github.com/jadeblaquiere/websocket-client"
)

const (
	DefaultWatchdogTimeout = 150 * time.Second
	DefaultTimeTickle      = 30 * time.Second
	DefaultStatusTickle    = 300 * time.Second
	DefaultPeersTickle     = 300 * time.Second
)

type WSDisconnectFunc func()

type WSProtocolHandler interface {
	TxHeader(rmh MessageHeader)
	OnDisconnect(f WSDisconnectFunc)
	Status() *StatusResponse
}

func NewWSProtocolHandler(con cwebsocket.ClientConnection, local *LocalHeaderCache, remote *HeaderCache) WSProtocolHandler {
	wsh := wsHandler{
		con:    con,
		local:  local,
		remote: remote,
	}
	wsh.setup()
	return &wsh
}

type wsHandler struct {
	con          cwebsocket.ClientConnection
	local        *LocalHeaderCache
	remote       *HeaderCache
	tmpStatus    StatusResponse
	disconnect   WSDisconnectFunc
	watchdog     *time.Timer
	timeTickle   *time.Timer
	statusTickle *time.Timer
	peersTickle  *time.Timer
}

func (wsh *wsHandler) resetTimeTickle() {
	if !wsh.timeTickle.Stop() {
		<-wsh.timeTickle.C
	}
	wsh.timeTickle.Reset(DefaultTimeTickle)
	wsh.resetWatchdog()
}

func (wsh *wsHandler) resetStatusTickle() {
	if !wsh.statusTickle.Stop() {
		<-wsh.statusTickle.C
	}
	wsh.statusTickle.Reset(DefaultStatusTickle)
	wsh.resetWatchdog()
}

func (wsh *wsHandler) resetWatchdog() {
	if !wsh.watchdog.Stop() {
		<-wsh.watchdog.C
	}
	wsh.watchdog.Reset(DefaultWatchdogTimeout)
}

func (wsh *wsHandler) txTime(t int) {
	wsh.resetTimeTickle()
	if wsh.remote != nil {
		fmt.Printf("tx->TIME to %s:%d\n", wsh.remote.host, wsh.remote.port)
	} else {
		fmt.Printf("tx->TIME to Pending Peer\n")
	}
	wsh.con.Emit("response-time", int(time.Now().Unix()))
}

func (wsh *wsHandler) rxTime(t int) {
	wsh.resetWatchdog()
	if wsh.remote != nil {
		fmt.Printf("rx<-TIME from %s:%d\n", wsh.remote.host, wsh.remote.port)
		wsh.remote.serverTime = uint32(t)
	}
}

func (wsh *wsHandler) txStatus(t int) {
	wsh.resetWatchdog()
	j, err := json.Marshal(wsh.local.Status())
	if err == nil {
		if wsh.remote != nil {
			fmt.Printf("tx->STATUS to %s:%d\n", wsh.remote.host, wsh.remote.port)
		} else {
			fmt.Printf("tx->STATUS to Pending Peer\n")
		}
		wsh.con.Emit("response-status", j)
	}
}

func (wsh *wsHandler) rxStatus(m []byte) {
	var status StatusResponse
	err := json.Unmarshal(m, &status)
	if err == nil {
		wsh.resetStatusTickle()
		if wsh.remote != nil {
			fmt.Printf("rx<-STATUS from %s:%d\n", wsh.remote.host, wsh.remote.port)
			wsh.remote.status = status
		} else {
			fmt.Printf("rx<-STATUS from Pending Peer %s:%d\n", status.Network.Host, status.Network.MSGPort)
			wsh.tmpStatus = status
		}
	}
}

func (wsh *wsHandler) txPeers(t int) {
	wsh.resetWatchdog()
	peers := wsh.local.ListPeers()
	for _, peer := range peers {
		j, err := json.Marshal(peer)
		if err == nil {
			if wsh.remote != nil {
				fmt.Printf("tx->PEER %s:%d to %s:%d\n", peer.Host, peer.Port, wsh.remote.host, wsh.remote.port)
			} else {
				fmt.Printf("tx->PEER %s:%d to Pending Peer\n", peer.Host, peer.Port)
			}
			wsh.con.Emit("response-peer", j)
		}
	}
}

func (wsh *wsHandler) rxPeer(m []byte) {
	wsh.resetWatchdog()
	var peer PeerItemResponse
	err := json.Unmarshal(m, &peer)
	if err == nil {
		if wsh.remote != nil {
			fmt.Printf("rx<-PEER %s:%d from %s:%d\n", peer.Host, peer.Port, wsh.remote.host, wsh.remote.port)
		} else {
			fmt.Printf("rx<-PEER %s:%d from Pending Peer\n", peer.Host, peer.Port)
		}
		wsh.local.AddPeer(peer.Host, peer.Port)
	}
}

func (wsh *wsHandler) TxHeader(rmh MessageHeader) {
	fmt.Printf("tx->HEADER to %s:%d\n", wsh.remote.host, wsh.remote.port)
	wsh.con.Emit("response-header", rmh.Serialize())
}

func (wsh *wsHandler) rxHeader(s string) {
	rmh := &RawMessageHeader{}
	err := rmh.Deserialize(s)
	if err == nil {
		wsh.resetWatchdog()
		if wsh.remote != nil {
			fmt.Printf("rx<-HEADER from %s:%d\n", wsh.remote.host, wsh.remote.port)
			insert, err := wsh.remote.Insert(rmh)
			if err != nil {
				return
			}
			if insert {
				_, _ = wsh.local.Insert(rmh)
			}
		} else {
			fmt.Printf("rx<-HEADER from Pending Peer\n")
		}
	} else {
		fmt.Printf("rx<-HEADER, error deserializing %s (len %d)\n", s, len(s))
	}
}

func (wsh *wsHandler) OnDisconnect(f WSDisconnectFunc) {
	wsh.disconnect = f
}

func (wsh *wsHandler) Status() *StatusResponse {
	if wsh.remote != nil {
		return &wsh.remote.status
	} else {
		return &wsh.tmpStatus
	}
}

func (wsh *wsHandler) setup() {
	wsh.watchdog = time.NewTimer(DefaultWatchdogTimeout)
	wsh.timeTickle = time.NewTimer(DefaultTimeTickle)
	wsh.statusTickle = time.NewTimer(DefaultStatusTickle)
	wsh.peersTickle = time.NewTimer(DefaultPeersTickle)
	wsh.con.On("request-time", wsh.txTime)
	wsh.con.On("response-time", wsh.rxTime)
	wsh.con.On("request-status", wsh.txStatus)
	wsh.con.On("response-status", wsh.rxStatus)
	wsh.con.On("response-header", wsh.rxHeader)
	wsh.con.On("request-peers", wsh.txPeers)
	wsh.con.On("response-peer", wsh.rxPeer)
	wsh.con.OnDisconnect(func() {
		if wsh.disconnect != nil {
			wsh.disconnect()
		}
	})

	go wsh.eventLoop()
	go wsh.txPeers(0)
}

func (wsh *wsHandler) eventLoop() {
	for {
		select {
		case <-wsh.watchdog.C:
			fmt.Println("Watchdog expired, closing connection")
			wsh.con.Disconnect()
			if wsh.disconnect != nil {
				wsh.disconnect()
			}
			return
		case <-wsh.timeTickle.C:
			if wsh.remote != nil {
				fmt.Printf("tx->TIME REQUEST to %s:%d\n", wsh.remote.host, wsh.remote.port)
			} else {
				fmt.Printf("tx->TIME REQUEST to Pending Peer\n")
			}
			wsh.con.Emit("request-time", int(0))
			wsh.timeTickle.Reset(DefaultTimeTickle)
			continue
		case <-wsh.statusTickle.C:
			if wsh.remote != nil {
				fmt.Printf("tx->STATUS REQUEST to %s:%d\n", wsh.remote.host, wsh.remote.port)
			} else {
				fmt.Printf("tx->STATUS REQUEST to Pending Peer\n")
			}
			wsh.con.Emit("request-status", int(0))
			wsh.statusTickle.Reset(DefaultStatusTickle)
			continue
		case <-wsh.peersTickle.C:
			if wsh.remote != nil {
				fmt.Printf("tx->PEERS REQUEST to %s:%d\n", wsh.remote.host, wsh.remote.port)
			} else {
				fmt.Printf("tx->PEERS REQUEST to Pending Peer\n")
			}
			wsh.con.Emit("request-peers", int(0))
			wsh.statusTickle.Reset(DefaultStatusTickle)
			continue
		}
	}
}

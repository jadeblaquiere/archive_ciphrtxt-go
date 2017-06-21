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
	"time"

	cwebsocket "github.com/jadeblaquiere/websocket-client"
)

const (
	DefaultWatchdogTimeout = 150 * time.Second
	DefaultTimeTickle      = 30 * time.Second
)

type WSDisconnect func(wsh *WSHandler)

type WSHandler struct {
	con        cwebsocket.ClientConnection
	local      *MessageStore
	remote     *HeaderCache
	disconnect WSDisconnect
	watchdog   *time.Timer
	timeTickle *time.Timer
}

func (wsh *WSHandler) resetTimeTickle() {
	if !wsh.timeTickle.Stop() {
		<-wsh.timeTickle.C
	}
	wsh.timeTickle.Reset(DefaultTimeTickle)
	wsh.resetWatchdog()
}

func (wsh *WSHandler) resetWatchdog() {
	if !wsh.watchdog.Stop() {
		<-wsh.watchdog.C
	}
	wsh.watchdog.Reset(DefaultWatchdogTimeout)
}

func (wsh *WSHandler) txTime(t int) {
	wsh.resetTimeTickle()
	wsh.con.Emit("response-time", int(time.Now().Unix()))
}

func (wsh *WSHandler) rxTime(t int) {
	wsh.remote.serverTime = uint32(t)
}

func (wsh *WSHandler) txStatus(t int) {
	j, err := json.Marshal(wsh.local.Status())
	if err == nil {
		wsh.con.Emit("response-status", j)
	}
}

func (wsh *WSHandler) rxStatus(m []byte) {
	var status StatusResponse
	err := json.Unmarshal(m, &status)
	if err == nil {
		wsh.remote.status = status
	}
}

func (wsh *WSHandler) TxHeader(rmh *RawMessageHeader) {
	wsh.con.Emit("response-header", rmh.Serialize())
}

func (wsh *WSHandler) rxHeader(s string) {
	rmh := &RawMessageHeader{}
	err := rmh.Deserialize(s)
	if err == nil {
		insert, err := wsh.remote.Insert(rmh)
		if err != nil {
			return
		}
		if insert {
			_, _ = wsh.local.LHC.Insert(rmh)
		}
	}
}

func (wsh *WSHandler) OnDisconnect(f WSDisconnect) {
	wsh.disconnect = f
}

func (wsh *WSHandler) Setup() {
	wsh.con.On("request-time", wsh.txTime)
	wsh.con.On("response-time", wsh.rxTime)
	wsh.con.On("request-status", wsh.txStatus)
	wsh.con.On("response-status", wsh.rxStatus)
	wsh.con.On("response-header", wsh.rxHeader)
	wsh.con.OnDisconnect(func() {
		if wsh.disconnect != nil {
			wsh.disconnect(wsh)
		}
	})
	wsh.timeTickle = time.NewTimer(DefaultTimeTickle)
	wsh.watchdog = time.NewTimer(DefaultWatchdogTimeout)

	go wsh.eventLoop()
}

func (wsh *WSHandler) eventLoop() {
	for {
		select {
		case <-wsh.watchdog.C:
			wsh.con.Disconnect()
			if wsh.disconnect != nil {
				wsh.disconnect(wsh)
			}
			return
		case <-wsh.timeTickle.C:
			wsh.con.Emit("request-time", int(0))
			wsh.timeTickle.Reset(DefaultTimeTickle)
		}
	}
}

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

package main

import (
    "flag"
    "fmt"
    //"log"
    //"net/http"
    //"crypto/elliptic"
    "crypto/rand"
    "encoding/hex"
    "io"
    "math/big"
    "os"
    "runtime"
    "sort"
    "strconv"
    "time"
    
    "github.com/jadeblaquiere/cttd/btcec"
    "github.com/jadeblaquiere/ciphrtxt-go/ciphrtxt"
    "github.com/kataras/iris"
    "github.com/iris-contrib/middleware/logger"
)

var ms *ciphrtxt.MessageStore
var privKey *btcec.PrivateKey
var pubKey *btcec.PublicKey

//var configRPCUser      =   flag.String("rpcuser",          "", "Token Service RPC username")
//var configRPCPass      =   flag.String("rpcpass",          "", "Token Service RPC password")
//var configRPCPass      =   flag.String("rpcpass", "127.0.0.1", "Token Service RPC hostname/ip")
//var configExtTokenHost = flag.String("tokenhost",          "", "Token Service advertised hostname/ip")
var configExtTokenPort =    flag.Int("tokenport",        7764, "Token Service advertised port number")
var configExternalHost =   flag.String("exthost",          "", "Message Service advertised hostname/ip")
var configExternalPort =      flag.Int("extport",        8080, "Message Service advertised port number")
var configListenPort   =   flag.Int("listenport",        8080, "Message Service listen port number")

func main() {
    nCpu := runtime.NumCPU()
    nCpuOrig := runtime.GOMAXPROCS(nCpu)
    
    fmt.Printf("setting GOMAXPROCS to %d (was %d)\n", nCpu, nCpuOrig)

    flag.Parse()

    curve := btcec.S256()
    p := curve.Params().P
    
    //fmt.Printf("p = %s\n", p.Text(16))
    
    privKeyInt, _ := rand.Int(rand.Reader, p)
    privKey, pubKey = btcec.PrivKeyFromBytes(curve, privKeyInt.Bytes())
    
    //fmt.Printf("privkey = %s\n", privKeyInt.Text(16))
    //fmt.Printf("privkey = %s\n", hex.EncodeToString(privKey.Serialize()))
    fmt.Printf("Ephemeral Pubkey  = %s\n", hex.EncodeToString(pubKey.SerializeCompressed()))
    
    lhc, err := ciphrtxt.OpenLocalHeaderCache("headers")
    if err != nil {
        fmt.Println("whoops:", err)
        return
    }
    defer lhc.Close()
    
    lhc.AddPeer("indigo.ciphrtxt.com",7754)
    lhc.AddPeer("violet.ciphrtxt.com",7754)
    
    lhc.Sync()
    
    startbig, _ := rand.Int(rand.Reader, big.NewInt(0x200))
    startbin := int(startbig.Int64()) + 0x200
    target := ciphrtxt.ShardSector{
        Start: startbin,
        Ring: 0,
    }

    ms, err = ciphrtxt.OpenMessageStore("./messages", lhc, startbin)
    if err != nil {
        fmt.Println("whoops:", err)
        return
    }
    defer ms.Close()
    
    ms.SetTarget(target)
    
    customLogger := logger.New(logger.Config{
		Status: true,
		IP: true,
		Method: true,
		Path: true,
	})

	go func(ms *ciphrtxt.MessageStore, interval int) {
        for {
            //fmt.Printf("msgstore.refresh calling Sleep()\n")
            time.Sleep(time.Second * time.Duration(interval/2))
            //fmt.Printf("msgstore.refresh calling Sync()\n")
            ms.Sync()
            //fmt.Printf("msgstore.refresh calling Sleep()\n")
            time.Sleep(time.Second * time.Duration(interval/2))
            //fmt.Printf("msgstore.refresh calling DiscoverPeers()\n")
            ms.LHC.DiscoverPeers(*configExternalHost, uint16(*configExternalPort))
            fmt.Printf("Refresh Status :%s:\n%s\n", time.Now().UTC().Format("2006-01-02 15:04:05"), ms.RefreshStatus())
        }
    } (ms, 60)
    
    ms.LHC.DiscoverPeers(*configExternalHost, uint16(*configExternalPort))
    
    api := iris.New()
    api.Use(customLogger)
    api.Get("/", index)
    api.Get("/api/v2/headers", get_headers)
    api.Get("/api/v2/headers/:msgid", get_header_info)
    api.Get("/api/v2/messages", get_messages)
    api.Get("/api/v2/messages/:msgid", download_message)
    api.Post("/api/v2/messages", upload_message)
    api.Get("/api/v2/peers", get_peers)
    api.Post("/api/v2/peers", add_peer)
    api.Get("/api/v2/status", get_status)
    api.Get("/api/v2/time", get_time)
    api.Get("/index", index)
    api.Get("/index.html", index)
    api.Get("/peers.html", peers)
    api.StaticWeb("/static", "./static", 1)
    listenString := ":" + strconv.Itoa(*configListenPort)
    api.Listen(listenString)
    //api.Listen(":8080")
}

func index(ctx *iris.Context){
    now := uint32(time.Now().Unix())
    lastHr, err := ms.FindSince(now - 3600)
    sort.Sort(sort.Reverse(ciphrtxt.MessageFileSlice(lastHr)))
    if err != nil {
        ctx.EmitError(iris.StatusInternalServerError)
        return
    }
    msgs := make([]ciphrtxt.MessageHeaderJSON,0)
    for _, m := range lastHr {
        msgs = append(msgs, *(m.RawMessageHeader.JSON()))
    }
    ctx.Render("index.html", struct { TimeMinus5 int; Messages []ciphrtxt.MessageHeaderJSON }{ TimeMinus5: int(time.Now().Unix() - 300), Messages: msgs })
}

func peers(ctx *iris.Context){
    peerInfo := make([]ciphrtxt.PeerJSON, 0)
    now := uint32(time.Now().Unix())
    lhc := ms.LHC
    for _, p := range lhc.Peers {
        pi := p.HC.GetPeerStatsJSON()
        peerInfo = append(peerInfo, *pi)
    }
    ctx.Render("peers.html", struct { TimeMinus5 int; Peers []ciphrtxt.PeerJSON }{ TimeMinus5: int(now - 300), Peers: peerInfo })
}

func get_headers(ctx *iris.Context){
    since, err := ctx.URLParamInt("since")
    if err != nil {
        since = 0
    } //else {
    //    fmt.Printf("GetHeaders: since = %d\n", since)
    //}
    
    lhc := ms.LHC
    hdrs, err := lhc.FindSince(uint32(since))
    if err != nil {
        ctx.EmitError(iris.StatusInternalServerError)
        return
    }
    res := make([]string, len(hdrs))
    
    for i, h := range hdrs {
        res[i] = h.Serialize()
    }

    ctx.JSON(iris.StatusOK, ciphrtxt.HeaderListResponse{Headers: res})
}

func get_header_info(ctx *iris.Context){
    msgid := ctx.Param("msgid")
    I, err := hex.DecodeString(msgid)
    if err != nil {
        ctx.EmitError(iris.StatusBadRequest)
        return
    }
    
    m, err := ms.FindByI(I)
    if err != nil {
        ctx.EmitError(iris.StatusNotFound)
        return
    }

    if m == nil {
        ctx.EmitError(iris.StatusNotFound)
        return
    }

    ctx.JSON(iris.StatusOK, m.RawMessageHeader.JSON())
}

func get_messages(ctx *iris.Context){
    since, err := ctx.URLParamInt("since")
    if err != nil {
        since = 0
    } //else {
    //    fmt.Printf("since = %d\n", since)
    //}
    
    msgs, err := ms.FindSince(uint32(since))
    if err != nil {
        ctx.EmitError(iris.StatusInternalServerError)
        return
    }
    res := make([]string, len(msgs))
    
    for i, m := range msgs {
        res[i] = hex.EncodeToString(m.IKey())
    }

    ctx.JSON(iris.StatusOK, ciphrtxt.MessageListResponse{Messages: res})
}

func get_peers(ctx *iris.Context){
    plr := ms.LHC.ListPeers()

    ctx.JSON(iris.StatusOK, plr)
}

func add_peer(ctx *iris.Context){
    var pir ciphrtxt.PeerItemResponse
    
    err := ctx.ReadJSON(&pir)
    if err != nil {
        ctx.EmitError(iris.StatusBadRequest)
        return
    }
    
    fmt.Printf("received add_peer for %s:%d\n", pir.Host, pir.Port)
    
    ms.LHC.AddPeer(pir.Host, pir.Port)

    ctx.Text(iris.StatusOK, "")
}

func download_message(ctx *iris.Context){
    msgid := ctx.Param("msgid")
    I, err := hex.DecodeString(msgid)
    if err != nil {
        ctx.EmitError(iris.StatusBadRequest)
        return
    }
    
    m, err := ms.FindOrFetchByI(I)
    if err != nil {
        ctx.EmitError(iris.StatusNotFound)
        return
    }

    if m == nil {
        ctx.EmitError(iris.StatusNotFound)
        return
    }

    ctx.ServeFile(m.Filepath, false)
}

func upload_message(ctx *iris.Context){
    message, err := ctx.FormFile("message")
    if err != nil {
        ctx.EmitError(iris.StatusInternalServerError)
        return
    }
    src, err := message.Open()
    if err != nil {
       ctx.EmitError(iris.StatusInternalServerError)
       return
    }
    defer src.Close()

    recvpath := "./receive/"+ strconv.Itoa(int(time.Now().UnixNano()))
    dst, err := os.Create(recvpath)
    if err != nil {
        ctx.EmitError(iris.StatusInternalServerError)
        return
    }
    
    if _, err = io.Copy(dst, src); err != nil {
       ctx.EmitError(iris.StatusInternalServerError)
       dst.Close()
       return
    }
    
    dst.Close()
    
    m := ciphrtxt.Ingest(recvpath)
    if m == nil {
        ctx.EmitError(iris.StatusBadRequest)
        return
    }
    
    Ihex := hex.EncodeToString(m.IKey())
    filemove := "./messages/store/" + Ihex[:4] + "/" + Ihex 
    //fmt.Printf("moving to %s\n", filemove)
    err = m.Move(filemove)
    if err != nil {
        ctx.EmitError(iris.StatusInternalServerError)
        return
    }
                
    servertime, err := ms.InsertFile(filemove)
    if err != nil {
        ctx.EmitError(iris.StatusInternalServerError)
        return
    }
    
    ctx.JSON(iris.StatusOK, ciphrtxt.MessageUploadResponse{Header: m.RawMessageHeader.Serialize(), Servertime: servertime})
}

func get_status(ctx *iris.Context){
    r_storage := ciphrtxt.StatusStorageResponse {
        Headers: ms.LHC.Count,
        Messages: ms.Count,
        Maxfilesize: (8*1024*1024),
        Capacity: (256*1024*1024*1024),
        Used: 0,
    }

    r_network := ciphrtxt.StatusNetworkResponse {
        Host: *configExternalHost,
        MSGPort: *configExternalPort,
        TOKPort: *configExtTokenPort,
    }

    r_target := ms.GetCurrentTarget()
    r_sector := ciphrtxt.ShardSector {
        Start: r_target.Start,
        Ring: r_target.Ring,
    }

    r_status := ciphrtxt.StatusResponse {
        Network: r_network,
        Pubkey: hex.EncodeToString(pubKey.SerializeCompressed()),
        Storage: r_storage,
        Sector: r_sector,
        Version: "0.2.0",
    }

    ctx.JSON(iris.StatusOK, r_status)
}

func get_time(ctx *iris.Context){
    
    ctx.JSON(iris.StatusOK, ciphrtxt.TimeResponse{Time: int(time.Now().Unix())})
}


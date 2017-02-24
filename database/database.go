// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package database keeps track of flow information
package database

import (
	"compress/gzip"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"tflow2/avltree"
	"tflow2/netflow"
	"tflow2/nfserver"
	"time"
	"unsafe"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
)

// TimeGroup groups all indices to flows of a particular router at a particular
// time into one object
type TimeGroup struct {
	Any       map[int]*avltree.Tree // Workaround: Why a map? Because: cannot assign to flows[fl.Timestamp][rtr].Any
	SrcAddr   map[string]*avltree.Tree
	DstAddr   map[string]*avltree.Tree
	Protocol  map[uint32]*avltree.Tree
	IntIn     map[uint32]*avltree.Tree
	IntOut    map[uint32]*avltree.Tree
	NextHop   map[string]*avltree.Tree
	SrcAs     map[uint32]*avltree.Tree
	DstAs     map[uint32]*avltree.Tree
	NextHopAs map[uint32]*avltree.Tree
	SrcPfx    map[string]*avltree.Tree
	DstPfx    map[string]*avltree.Tree
	SrcPort   map[uint32]*avltree.Tree
	DstPort   map[uint32]*avltree.Tree
	Locks     *LockGroup
}

// LockGroup is a group of locks suitable to lock any particular member of TimeGroup
type LockGroup struct {
	Any       sync.RWMutex
	SrcAddr   sync.RWMutex
	DstAddr   sync.RWMutex
	Protocol  sync.RWMutex
	IntIn     sync.RWMutex
	IntOut    sync.RWMutex
	NextHop   sync.RWMutex
	SrcAs     sync.RWMutex
	DstAs     sync.RWMutex
	NextHopAs sync.RWMutex
	SrcPfx    sync.RWMutex
	DstPfx    sync.RWMutex
	SrcPort   sync.RWMutex
	DstPort   sync.RWMutex
}

// FlowsByTimeRtr holds all keys (and thus is the only way) to our flows
type FlowsByTimeRtr map[int64]map[string]TimeGroup

// FlowDatabase represents a flow database object
type FlowDatabase struct {
	flows       FlowsByTimeRtr
	lock        sync.RWMutex
	maxAge      int64
	aggregation int64
	lastDump    int64
	compLevel   int
	samplerate  int
	storage     string
	debug       int
	Input       chan *netflow.Flow
}

// New creates a new FlowDatabase and returns a pointer to it
func New(aggregation int64, maxAge int64, numAddWorker int, samplerate int, debug int, compLevel int, storage string) *FlowDatabase {
	flowDB := &FlowDatabase{
		maxAge:      maxAge,
		aggregation: aggregation,
		compLevel:   compLevel,
		samplerate:  samplerate,
		Input:       make(chan *netflow.Flow),
		lastDump:    time.Now().Unix(),
		storage:     storage,
		debug:       debug,
		flows:       make(FlowsByTimeRtr),
	}

	for i := 0; i < numAddWorker; i++ {
		go func() {
			for {
				fl := <-flowDB.Input
				flowDB.Add(fl)
			}
		}()

		go func() {
			for {
				// Set a timer and wait for our next run
				event := time.NewTimer(time.Duration(flowDB.aggregation) * time.Second)
				<-event.C
				flowDB.CleanUp()
			}
		}()

		go func() {
			for {
				// Set a timer and wait for our next run
				event := time.NewTimer(time.Duration(flowDB.aggregation) * time.Second)
				<-event.C
				flowDB.Dumper()
			}
		}()
	}
	return flowDB
}

// Add adds flow `fl` to database fdb
func (fdb *FlowDatabase) Add(fl *netflow.Flow) {
	// build indices for map access
	rtrip := net.IP(fl.Router)
	rtr := rtrip.String()
	srcAddr := net.IP(fl.SrcAddr).String()
	dstAddr := net.IP(fl.DstAddr).String()
	nextHopAddr := net.IP(fl.NextHop).String()
	srcPfx := fl.SrcPfx.String()
	dstPfx := fl.DstPfx.String()

	fdb.lock.Lock()
	// Check if timestamp entry exists already. If not, create it.
	if _, ok := fdb.flows[fl.Timestamp]; !ok {
		fdb.flows[fl.Timestamp] = make(map[string]TimeGroup)
	}

	// Check if router entry exists already. If not, create it.
	if _, ok := fdb.flows[fl.Timestamp][rtr]; !ok {
		fdb.flows[fl.Timestamp][rtr] = TimeGroup{
			Any:       make(map[int]*avltree.Tree),
			SrcAddr:   make(map[string]*avltree.Tree),
			DstAddr:   make(map[string]*avltree.Tree),
			Protocol:  make(map[uint32]*avltree.Tree),
			IntIn:     make(map[uint32]*avltree.Tree),
			IntOut:    make(map[uint32]*avltree.Tree),
			NextHop:   make(map[string]*avltree.Tree),
			SrcAs:     make(map[uint32]*avltree.Tree),
			DstAs:     make(map[uint32]*avltree.Tree),
			NextHopAs: make(map[uint32]*avltree.Tree),
			SrcPfx:    make(map[string]*avltree.Tree),
			DstPfx:    make(map[string]*avltree.Tree),
			SrcPort:   make(map[uint32]*avltree.Tree),
			DstPort:   make(map[uint32]*avltree.Tree),
			Locks:     &LockGroup{},
		}
	}
	fdb.lock.Unlock()

	fdb.lock.RLock()
	defer fdb.lock.RUnlock()
	if _, ok := fdb.flows[fl.Timestamp]; !ok {
		glog.Warningf("stopped adding data for %d: already deleted", fl.Timestamp)
		return
	}

	locks := fdb.flows[fl.Timestamp][rtr].Locks

	// Start the actual insertion into indices
	locks.Any.Lock()
	if fdb.flows[fl.Timestamp][rtr].Any[0] == nil {
		fdb.flows[fl.Timestamp][rtr].Any[0] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].Any[0].Insert(fl, fl, ptrIsSmaller)
	locks.Any.Unlock()

	locks.SrcAddr.Lock()
	if fdb.flows[fl.Timestamp][rtr].SrcAddr[srcAddr] == nil {
		fdb.flows[fl.Timestamp][rtr].SrcAddr[srcAddr] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].SrcAddr[srcAddr].Insert(fl, fl, ptrIsSmaller)
	locks.SrcAddr.Unlock()

	locks.DstAddr.Lock()
	if fdb.flows[fl.Timestamp][rtr].DstAddr[dstAddr] == nil {
		fdb.flows[fl.Timestamp][rtr].DstAddr[dstAddr] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].DstAddr[dstAddr].Insert(fl, fl, ptrIsSmaller)
	locks.DstAddr.Unlock()

	locks.Protocol.Lock()
	if fdb.flows[fl.Timestamp][rtr].Protocol[fl.Protocol] == nil {
		fdb.flows[fl.Timestamp][rtr].Protocol[fl.Protocol] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].Protocol[fl.Protocol].Insert(fl, fl, ptrIsSmaller)
	locks.Protocol.Unlock()

	locks.IntIn.Lock()
	if fdb.flows[fl.Timestamp][rtr].IntIn[fl.IntIn] == nil {
		fdb.flows[fl.Timestamp][rtr].IntIn[fl.IntIn] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].IntIn[fl.IntIn].Insert(fl, fl, ptrIsSmaller)
	locks.IntIn.Unlock()

	locks.IntOut.Lock()
	if fdb.flows[fl.Timestamp][rtr].IntOut[fl.IntOut] == nil {
		fdb.flows[fl.Timestamp][rtr].IntOut[fl.IntOut] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].IntOut[fl.IntOut].Insert(fl, fl, ptrIsSmaller)
	locks.IntOut.Unlock()

	locks.NextHop.Lock()
	if fdb.flows[fl.Timestamp][rtr].NextHop[nextHopAddr] == nil {
		fdb.flows[fl.Timestamp][rtr].NextHop[nextHopAddr] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].NextHop[nextHopAddr].Insert(fl, fl, ptrIsSmaller)
	locks.NextHop.Unlock()

	locks.SrcAs.Lock()
	if fdb.flows[fl.Timestamp][rtr].SrcAs[fl.SrcAs] == nil {
		fdb.flows[fl.Timestamp][rtr].SrcAs[fl.SrcAs] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].SrcAs[fl.SrcAs].Insert(fl, fl, ptrIsSmaller)
	locks.SrcAs.Unlock()

	locks.DstAs.Lock()
	if fdb.flows[fl.Timestamp][rtr].DstAs[fl.DstAs] == nil {
		fdb.flows[fl.Timestamp][rtr].DstAs[fl.DstAs] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].DstAs[fl.DstAs].Insert(fl, fl, ptrIsSmaller)
	locks.DstAs.Unlock()

	locks.NextHopAs.Lock()
	if fdb.flows[fl.Timestamp][rtr].NextHopAs[fl.NextHopAs] == nil {
		fdb.flows[fl.Timestamp][rtr].NextHopAs[fl.NextHopAs] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].NextHopAs[fl.NextHopAs].Insert(fl, fl, ptrIsSmaller)
	locks.NextHopAs.Unlock()

	locks.SrcPfx.Lock()
	if fdb.flows[fl.Timestamp][rtr].SrcPfx[srcPfx] == nil {
		fdb.flows[fl.Timestamp][rtr].SrcPfx[srcPfx] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].SrcPfx[srcPfx].Insert(fl, fl, ptrIsSmaller)
	locks.SrcPfx.Unlock()

	locks.DstPfx.Lock()
	if fdb.flows[fl.Timestamp][rtr].DstPfx[dstPfx] == nil {
		fdb.flows[fl.Timestamp][rtr].DstPfx[dstPfx] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].DstPfx[dstPfx].Insert(fl, fl, ptrIsSmaller)
	locks.DstPfx.Unlock()

	locks.SrcPort.Lock()
	if fdb.flows[fl.Timestamp][rtr].SrcPort[fl.SrcPort] == nil {
		fdb.flows[fl.Timestamp][rtr].SrcPort[fl.SrcPort] = avltree.New()
	}
	fdb.flows[fl.Timestamp][rtr].SrcPort[fl.SrcPort].Insert(fl, fl, ptrIsSmaller)
	locks.SrcPort.Unlock()
}

// CleanUp deletes all flows from database `fdb` that are older than `maxAge` seconds
func (fdb *FlowDatabase) CleanUp() {
	now := time.Now().Unix()
	now = now - now%fdb.aggregation

	fdb.lock.Lock()
	defer fdb.lock.Unlock()
	for ts := range fdb.flows {
		if ts < now-fdb.maxAge {
			delete(fdb.flows, ts)
		}
	}
}

// Dumper dumps all flows in `fdb` to hard drive that haven't been dumped yet
func (fdb *FlowDatabase) Dumper() {
	fdb.lock.RLock()
	defer fdb.lock.RUnlock()

	min := atomic.LoadInt64(&fdb.lastDump)
	now := time.Now().Unix()
	max := (now - now%fdb.aggregation) - 2*fdb.aggregation
	atomic.StoreInt64(&fdb.lastDump, max)

	for ts := range fdb.flows {
		if ts < min || ts > max {
			continue
		}
		for router := range fdb.flows[ts] {
			go fdb.dumpToDisk(ts, router)
		}
		atomic.StoreInt64(&fdb.lastDump, ts)
	}
}

func (fdb *FlowDatabase) dumpToDisk(ts int64, router string) {
	fdb.lock.RLock()
	tree := fdb.flows[ts][router].Any[0]
	fdb.lock.RUnlock()

	flows := &netflow.Flows{}
	tree.Each(dump, flows)
	if fdb.debug > 1 {
		glog.Warningf("flows contains %d flows", len(flows.Flows))
	}
	buffer, err := proto.Marshal(flows)
	if err != nil {
		glog.Errorf("unable to marshal flows into pb: %v", err)
		return
	}

	ymd := fmt.Sprintf("%04d-%02d-%02d", time.Unix(ts, 0).Year(), time.Unix(ts, 0).Month(), time.Unix(ts, 0).Day())
	os.Mkdir(fmt.Sprintf("%s/%s", fdb.storage, ymd), 0700)

	fh, err := os.Create(fmt.Sprintf("%s/%s/nf-%d-%s.tflow2.pb.gzip", fdb.storage, ymd, ts, router))
	if err != nil {
		glog.Errorf("couldn't create file: %v", err)
	}
	defer fh.Close()

	// Compress data before writing it out to the disk
	gz, err := gzip.NewWriterLevel(fh, fdb.compLevel)
	if err != nil {
		glog.Errorf("invalud gzip compression level: %v", err)
		return
	}
	_, err = gz.Write(buffer)
	gz.Close()

	if err != nil {
		glog.Errorf("failed to write file: %v", err)
	}
}

func dump(node *avltree.TreeNode, vals ...interface{}) {
	flows := vals[0].(*netflow.Flows)
	flow := node.Value.(*netflow.Flow)
	flowcopy := *flow

	// Remove information about particular IP addresses for privacy reason
	flowcopy.SrcAddr = []byte{0, 0, 0, 0}
	flowcopy.DstAddr = []byte{0, 0, 0, 0}

	flows.Flows = append(flows.Flows, &flowcopy)
}

// ptrIsSmaller checks if uintptr c1 is smaller than uintptr c2
func ptrIsSmaller(c1 interface{}, c2 interface{}) bool {
	x := uintptr(unsafe.Pointer(c1.(*netflow.Flow)))
	y := uintptr(unsafe.Pointer(c2.(*netflow.Flow)))

	return x < y
}

// uint64IsSmaller checks if uint64 c1 is smaller than uint64 c2
func uint64IsSmaller(c1 interface{}, c2 interface{}) bool {
	return c1.(uint64) < c2.(uint64)
}

// uint64IsSmaller checks if int64 c1 is small than int64 c2
func int64IsSmaller(c1 interface{}, c2 interface{}) bool {
	return c1.(int64) < c2.(int64)
}

// dumpFlows dumps all flows a tree `tree`
func dumpFlows(tree *avltree.TreeNode) {
	tree.Each(printNode)
}

// printNode dumps the flow of `node` on the screen
func printNode(node *avltree.TreeNode, vals ...interface{}) {
	fl := node.Value.(*netflow.Flow)
	nfserver.Dump(fl)
}

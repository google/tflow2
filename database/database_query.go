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

package database

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"compress/gzip"

	"github.com/google/tflow2/avltree"
	"github.com/google/tflow2/convert"
	"github.com/google/tflow2/netflow"
	"github.com/google/tflow2/stats"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
)

// BreakDownMap defines by what fields data should be broken down in a query
type BreakDownMap struct {
	Router     bool
	Family     bool
	SrcAddr    bool
	DstAddr    bool
	Protocol   bool
	IntIn      bool
	IntOut     bool
	NextHop    bool
	SrcAsn     bool
	DstAsn     bool
	NextHopAsn bool
	SrcPfx     bool
	DstPfx     bool
	SrcPort    bool
	DstPort    bool
}

// Condition represents a query condition
type Condition struct {
	Field    int
	Operator int
	Operand  []byte
}

// ConditionExt is external representation of a query condition
type ConditionExt struct {
	Field    int
	Operator int
	Operand  string
}

// Conditions represents a set of conditions of a query
type Conditions []Condition

// ConditionsExt is external representation of conditions of a query
type ConditionsExt []ConditionExt

// QueryExt represents a query in the way it is received from the frontend
type QueryExt struct {
	Cond      ConditionsExt
	Breakdown BreakDownMap
	TopN      int
}

// Query is the internal representation of a query
type Query struct {
	Cond      Conditions
	Breakdown BreakDownMap
	TopN      int
}

type concurrentResSum struct {
	Values map[string]uint64
	Lock   sync.Mutex
}

// These constants are used in communication with the frontend
const (
	OpEqual        = 0
	OpUnequal      = 1
	OpSmaller      = 2
	OpGreater      = 3
	FieldTimestamp = 0
	FieldRouter    = 1
	FieldSrcAddr   = 2
	FieldDstAddr   = 3
	FieldProtocol  = 4
	FieldIntIn     = 5
	FieldIntOut    = 6
	FieldNextHop   = 7
	FieldSrcAs     = 8
	FieldDstAs     = 9
	FieldNextHopAs = 10
	FieldSrcPfx    = 11
	FieldDstPfx    = 12
	FieldSrcPort   = 13
	FieldDstPort   = 14
)

// translateQuery translates a query from external representation to internal representaion
func translateQuery(e QueryExt) (Query, error) {
	var q Query
	q.Breakdown = e.Breakdown
	q.TopN = e.TopN

	for _, c := range e.Cond {
		var operand []byte

		switch c.Field {
		case FieldTimestamp:
			op, err := strconv.Atoi(c.Operand)
			if err != nil {
				return q, err
			}
			operand = convert.Int64Byte(int64(op))

		case FieldProtocol:
			op, err := strconv.Atoi(c.Operand)
			if err != nil {
				return q, err
			}
			operand = convert.Uint16Byte(uint16(op))

		case FieldSrcPort:
			op, err := strconv.Atoi(c.Operand)
			if err != nil {
				return q, err
			}
			operand = convert.Uint16Byte(uint16(op))

		case FieldDstPort:
			op, err := strconv.Atoi(c.Operand)
			if err != nil {
				return q, err
			}
			operand = convert.Uint16Byte(uint16(op))

		case FieldSrcAddr:
			operand = convert.IPByteSlice(c.Operand)

		case FieldDstAddr:
			operand = convert.IPByteSlice(c.Operand)

		case FieldRouter:
			operand = convert.IPByteSlice(c.Operand)

		case FieldIntIn:
			op, err := strconv.Atoi(c.Operand)
			if err != nil {
				return q, err
			}
			operand = convert.Uint16Byte(uint16(op))

		case FieldIntOut:
			op, err := strconv.Atoi(c.Operand)
			if err != nil {
				return q, err
			}
			operand = convert.Uint16Byte(uint16(op))

		case FieldNextHop:
			operand = convert.IPByteSlice(c.Operand)

		case FieldSrcAs:
			op, err := strconv.Atoi(c.Operand)
			if err != nil {
				return q, err
			}
			operand = convert.Uint32Byte(uint32(op))

		case FieldDstAs:
			op, err := strconv.Atoi(c.Operand)
			if err != nil {
				return q, err
			}
			operand = convert.Uint32Byte(uint32(op))

		case FieldNextHopAs:
			op, err := strconv.Atoi(c.Operand)
			if err != nil {
				return q, err
			}
			operand = convert.Uint32Byte(uint32(op))

		case FieldSrcPfx:
			_, pfx, err := net.ParseCIDR(string(c.Operand))
			if err != nil {
				return q, err
			}
			operand = []byte(pfx.String())

		case FieldDstPfx:
			_, pfx, err := net.ParseCIDR(string(c.Operand))
			if err != nil {
				return q, err
			}
			operand = []byte(pfx.String())
		}

		q.Cond = append(q.Cond, Condition{
			Field:    c.Field,
			Operator: c.Operator,
			Operand:  operand,
		})
	}

	return q, nil
}

// loadFromDisc loads netflow data from disk into in memory data structure
func (fdb *FlowDatabase) loadFromDisc(ts int64, router string, query Query, ch chan map[string]uint64, resSum *concurrentResSum) {
	res := avltree.New()
	ymd := fmt.Sprintf("%04d-%02d-%02d", time.Unix(ts, 0).Year(), time.Unix(ts, 0).Month(), time.Unix(ts, 0).Day())
	filename := fmt.Sprintf("%s/%s/nf-%d-%s.tflow2.pb.gzip", fdb.storage, ymd, ts, router)
	fh, err := os.Open(filename)
	if err != nil {
		if fdb.debug > 0 {
			glog.Errorf("unable to open file: %v", err)
		}
		ch <- nil
		return
	}
	if fdb.debug > 1 {
		glog.Infof("sucessfully opened file: %s", filename)
	}
	defer fh.Close()

	gz, err := gzip.NewReader(fh)
	if err != nil {
		glog.Errorf("unable to create gzip reader: %v", err)
		ch <- nil
		return
	}
	defer gz.Close()

	buffer, err := ioutil.ReadAll(gz)
	if err != nil {
		glog.Errorf("unable to gunzip: %v", err)
		ch <- nil
		return
	}

	// Unmarshal protobuf
	flows := netflow.Flows{}
	err = proto.Unmarshal(buffer, &flows)
	if err != nil {
		glog.Errorf("unable to unmarshal protobuf: %v", err)
		ch <- nil
		return
	}

	if fdb.debug > 1 {
		glog.Infof("file %s contains %d flows", filename, len(flows.Flows))
	}

	// Validate flows and add them to res tree
	for _, fl := range flows.Flows {
		if validateFlow(fl, query) {
			res.Insert(fl, fl, ptrIsSmaller)
		}
	}

	// Breakdown
	resTime := make(map[string]uint64)
	res.Each(breakdown, query.Breakdown, resSum, resTime)

	ch <- resTime
}

func validateFlow(fl *netflow.Flow, query Query) bool {
	for _, c := range query.Cond {
		switch c.Field {
		case FieldTimestamp:
			continue
		case FieldRouter:
			continue
		case FieldProtocol:
			if fl.Protocol != uint32(convert.Uint16b(c.Operand)) {
				return false
			}
			continue
		case FieldSrcAddr:
			if net.IP(fl.SrcAddr).String() != net.IP(c.Operand).String() {
				return false
			}
			continue
		case FieldDstAddr:
			if net.IP(fl.DstAddr).String() != net.IP(c.Operand).String() {
				return false
			}
			continue
		case FieldIntIn:
			if fl.IntIn != uint32(convert.Uint16b(c.Operand)) {
				return false
			}
			continue
		case FieldIntOut:
			if fl.IntOut != uint32(convert.Uint16b(c.Operand)) {
				return false
			}
			continue
		case FieldNextHop:
			if net.IP(fl.NextHop).String() != net.IP(c.Operand).String() {
				return false
			}
			continue
		case FieldSrcAs:
			if fl.SrcAs != convert.Uint32b(c.Operand) {
				return false
			}
			continue
		case FieldDstAs:
			if fl.DstAs != convert.Uint32b(c.Operand) {
				return false
			}
			continue
		case FieldNextHopAs:
			if fl.NextHopAs != convert.Uint32b(c.Operand) {
				return false
			}
		case FieldSrcPort:
			if fl.SrcPort != uint32(convert.Uint16b(c.Operand)) {
				return false
			}
			continue
		case FieldDstPort:
			if fl.DstPort != uint32(convert.Uint16b(c.Operand)) {
				return false
			}
			continue
		case FieldSrcPfx:
			if fl.SrcPfx.String() != string(c.Operand) {
				return false
			}
			continue
		case FieldDstPfx:
			if fl.DstPfx.String() != string(c.Operand) {
				return false
			}
			continue
		}
	}
	return true
}

// RunQuery executes a query and returns sends the result as JSON on `w`
func (fdb *FlowDatabase) RunQuery(query string) ([][]string, error) {
	queryStart := time.Now()
	stats.GlobalStats.Queries++
	var qe QueryExt
	err := json.Unmarshal([]byte(query), &qe)
	if err != nil {
		glog.Warningf("Unable unmarshal json query: %s", query)
		return nil, err
	}
	q, err := translateQuery(qe)
	if err != nil {
		glog.Warningf("Unable to translate query")
		return nil, err
	}

	// Determine router
	rtr := ""
	for _, c := range q.Cond {
		if c.Field == FieldRouter {
			iprtr := net.IP(c.Operand)
			rtr = iprtr.String()
		}
	}
	if rtr == "" {
		glog.Warningf("Router is mandatory cirteria")
		return nil, err
	}

	var start int64
	end := time.Now().Unix()

	// Determine time window
	for _, c := range q.Cond {
		if c.Field != FieldTimestamp {
			continue
		}
		switch c.Operator {
		case OpGreater:
			start = int64(convert.Uint64b(c.Operand))
		case OpSmaller:
			end = int64(convert.Uint64b(c.Operand))
		}
	}

	// Allign start point to `aggregation` raster
	start = start - (start % fdb.aggregation)

	resSum := &concurrentResSum{}
	resSum.Values = make(map[string]uint64)
	resTime := make(map[int64]map[string]uint64)
	resChannels := make(map[int64]chan map[string]uint64)

	for ts := start; ts < end; ts += fdb.aggregation {
		resChannels[ts] = make(chan map[string]uint64)
		fdb.lock.RLock()
		if _, ok := fdb.flows[ts]; !ok {
			fdb.lock.RUnlock()
			go fdb.loadFromDisc(ts, rtr, q, resChannels[ts], resSum)
			fdb.lock.RLock()
			if _, ok := fdb.flows[ts]; !ok {
				fdb.lock.RUnlock()
				continue
			}
		}

		// candidates keeps a list of all trees that fulfill the queries criteria
		candidates := make([]*avltree.Tree, 0)
		for _, c := range q.Cond {
			if fdb.debug > 1 {
				glog.Infof("Adding tree to cancidates list: Field: %d, Value: %d", c.Field, c.Operand)
			}
			switch c.Field {
			case FieldTimestamp:
				continue
			case FieldRouter:
				continue
			case FieldProtocol:
				candidates = append(candidates, fdb.flows[ts][rtr].Protocol[uint32(convert.Uint16b(c.Operand))])
			case FieldSrcAddr:
				candidates = append(candidates, fdb.flows[ts][rtr].SrcAddr[net.IP(c.Operand).String()])
			case FieldDstAddr:
				candidates = append(candidates, fdb.flows[ts][rtr].DstAddr[net.IP(c.Operand).String()])
			case FieldIntIn:
				candidates = append(candidates, fdb.flows[ts][rtr].IntIn[uint32(convert.Uint16b(c.Operand))])
			case FieldIntOut:
				candidates = append(candidates, fdb.flows[ts][rtr].IntOut[uint32(convert.Uint16b(c.Operand))])
			case FieldNextHop:
				candidates = append(candidates, fdb.flows[ts][rtr].NextHop[net.IP(c.Operand).String()])
			case FieldSrcAs:
				candidates = append(candidates, fdb.flows[ts][rtr].SrcAs[convert.Uint32b(c.Operand)])
			case FieldDstAs:
				candidates = append(candidates, fdb.flows[ts][rtr].DstAs[convert.Uint32b(c.Operand)])
			case FieldNextHopAs:
				candidates = append(candidates, fdb.flows[ts][rtr].NextHopAs[convert.Uint32b(c.Operand)])
			case FieldSrcPort:
				candidates = append(candidates, fdb.flows[ts][rtr].SrcPort[uint32(convert.Uint16b(c.Operand))])
			case FieldDstPort:
				candidates = append(candidates, fdb.flows[ts][rtr].DstPort[uint32(convert.Uint16b(c.Operand))])
			case FieldSrcPfx:
				candidates = append(candidates, fdb.flows[ts][rtr].SrcPfx[string(c.Operand)])
			case FieldDstPfx:
				candidates = append(candidates, fdb.flows[ts][rtr].DstPfx[string(c.Operand)])
			}
		}
		fdb.lock.RUnlock()

		go func(candidates []*avltree.Tree, ch chan map[string]uint64, ts int64) {
			if fdb.debug > 1 {
				glog.Infof("candidate trees: %d (%d)", len(candidates), ts)
			}

			// Find common elements of candidate trees
			res := avltree.Intersection(candidates)
			if res == nil {
				glog.Warningf("Interseciton Result was empty!")
				res = fdb.flows[ts][rtr].Any[0]
			}

			// Breakdown
			resTime := make(map[string]uint64)
			res.Each(breakdown, q.Breakdown, resSum, resTime)
			ch <- resTime
		}(candidates, resChannels[ts], ts)
	}

	// Reading results from go routines
	glog.Infof("Awaiting results from go routines")
	for ts := start; ts < end; ts += fdb.aggregation {
		glog.Infof("Waiting for results for ts %d", ts)
		resTime[ts] = <-resChannels[ts]
	}
	glog.Infof("Done reading results")

	// Build list of all keys
	keys := make([]string, 0)

	// Build Tree Bytes -> Key to allow efficient finding of top n flows
	var btree = avltree.New()
	for k, b := range resSum.Values {
		keys = append(keys, k)
		btree.Insert(b, k, uint64IsSmaller)
	}

	// Find top n keys
	topKeysList := btree.TopN(q.TopN)
	topKeys := make(map[string]int)
	for _, v := range topKeysList {
		topKeys[v.(string)] = 1
	}

	// Find all timestamps we have and get them sorted
	tsTree := avltree.New()
	for ts := range resTime {
		tsTree.Insert(ts, ts, int64IsSmaller)
	}
	timestamps := tsTree.Dump()

	queryResult := make([][]string, 0)

	// Construct table header
	headLine := make([]string, 0)
	headLine = append(headLine, "Time")
	for _, k := range topKeysList {
		headLine = append(headLine, k.(string))
	}
	headLine = append(headLine, "Rest")
	queryResult = append(queryResult, headLine)

	for _, ts := range timestamps {
		line := make([]string, 0)
		t := time.Unix(ts.(int64), 0)
		line = append(line, fmt.Sprintf("%02d:%02d:%02d", t.Hour(), t.Minute(), t.Second()))

		// Top flows
		buckets := resTime[ts.(int64)]
		for _, k := range topKeysList {
			if _, ok := buckets[k.(string)]; !ok {
				line = append(line, "0")
			} else {
				line = append(line, fmt.Sprintf("%d", buckets[k.(string)]/uint64(fdb.aggregation)*8*uint64(fdb.samplerate)))
			}
		}

		// Rest
		var rest uint64
		for k, v := range buckets {
			if _, ok := topKeys[k]; ok {
				continue
			}
			rest += v
		}
		line = append(line, fmt.Sprintf("%d", rest))
		queryResult = append(queryResult, line)
	}

	glog.Infof("Query %s took %d ns\n", query, time.Since(queryStart))
	return queryResult, nil
}

// breakdown build all possible relevant keys of flows for flows in tree `node`
// and builds sums for each key in order to allow us to find top combinations
func breakdown(node *avltree.TreeNode, vals ...interface{}) {
	if len(vals) != 3 {
		glog.Errorf("lacking arguments")
		return
	}

	bd := vals[0].(BreakDownMap)
	sums := vals[1].(*concurrentResSum)
	buckets := vals[2].(map[string]uint64)
	fl := node.Value.(*netflow.Flow)

	// Build format string to build key
	srcAddr := "_"
	dstAddr := "_"
	protocol := "_"
	intIn := "_"
	intOut := "_"
	nextHop := "_"
	srcAs := "_"
	dstAs := "_"
	nextHopAs := "_"
	srcPfx := "_"
	dstPfx := "_"
	srcPort := "_"
	dstPort := "_"

	if bd.SrcAddr {
		srcAddr = fmt.Sprintf("Src:%s", net.IP(fl.SrcAddr).String())
	}
	if bd.DstAddr {
		dstAddr = fmt.Sprintf("Dst:%s", net.IP(fl.DstAddr).String())
	}
	if bd.Protocol {
		protocol = fmt.Sprintf("Proto:%d", fl.Protocol)
	}
	if bd.IntIn {
		intIn = fmt.Sprintf("IntIn:%d", fl.IntIn)
	}
	if bd.IntOut {
		intOut = fmt.Sprintf("IntOut:%d", fl.IntOut)
	}
	if bd.NextHop {
		nextHop = fmt.Sprintf("NH:%s", net.IP(fl.NextHop).String())
	}
	if bd.SrcAsn {
		srcAs = fmt.Sprintf("SrcAS:%d", fl.SrcAs)
	}
	if bd.DstAsn {
		dstAs = fmt.Sprintf("DstAS:%d", fl.DstAs)
	}
	if bd.NextHopAsn {
		nextHopAs = fmt.Sprintf("NH_AS:%d", fl.NextHopAs)
	}
	if bd.SrcPfx {
		if fl.SrcPfx != nil {
			pfx := net.IPNet{
				IP:   fl.SrcPfx.IP,
				Mask: fl.SrcPfx.Mask,
			}
			srcPfx = fmt.Sprintf("SrcNet:%s", pfx.String())
		} else {
			srcPfx = fmt.Sprintf("SrcNet:0.0.0.0/0")
		}
	}
	if bd.DstPfx {
		if fl.DstPfx != nil {
			pfx := net.IPNet{
				IP:   fl.DstPfx.IP,
				Mask: fl.DstPfx.Mask,
			}
			dstPfx = fmt.Sprintf("DstNet:%s", pfx.String())
		} else {
			dstPfx = fmt.Sprintf("DstNet:0.0.0.0/0")
		}
	}
	if bd.SrcPort {
		srcPort = fmt.Sprintf("SrcPort:%d", fl.SrcPort)
	}
	if bd.DstPort {
		dstPort = fmt.Sprintf("DstPort:%d", fl.DstPort)
	}

	// Build key
	key := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", srcAddr, dstAddr, protocol, intIn, intOut, nextHop, srcAs, dstAs, nextHopAs, srcPfx, dstPfx, srcPort, dstPort)

	// Remove underscores from key
	key = strings.Replace(key, ",_,", ",", -1)
	key = strings.Replace(key, "_,", "", -1)
	key = strings.Replace(key, ",_", "", -1)

	// Remove leading and trailing commas
	parts := strings.Split(key, "")
	first := 0
	last := len(parts) - 1
	if parts[0] == "," {
		first++
	}
	if parts[last] == "," {
		last--
	}
	key = strings.Join(parts[first:last+1], "")

	// Build sum for key
	if _, ok := buckets[key]; !ok {
		buckets[key] = fl.Size
	} else {
		buckets[key] += fl.Size
	}

	// Build overall sum
	sums.Lock.Lock()
	if _, ok := sums.Values[key]; !ok {
		sums.Values[key] = fl.Size
	} else {
		sums.Values[key] += fl.Size
	}
	sums.Lock.Unlock()
}

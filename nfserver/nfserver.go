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

// Package nfserver provides netflow collection services via UDP and passes flows into annotator layer
package nfserver

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/golang/glog"
	"github.com/google/tflow2/convert"
	"github.com/google/tflow2/netflow"
	"github.com/google/tflow2/nf9"
	"github.com/google/tflow2/stats"
)

// fieldMap describes what information is at what index in the slice
// that we get from decoding a netflow packet
type fieldMap struct {
	srcAddr  int
	dstAddr  int
	protocol int
	packets  int
	size     int
	intIn    int
	intOut   int
	nextHop  int
	family   int
	vlan     int
	ts       int
	srcAsn   int
	dstAsn   int
	srcPort  int
	dstPort  int
}

// NetflowServer represents a Netflow Collector instance
type NetflowServer struct {
	// tmplCache is used to save received flow templates
	// for later lookup in order to decode netflow packets
	tmplCache *templateCache

	// receiver is the channel used to receive flows from the annotator layer
	Output chan *netflow.Flow

	// debug defines the debug level
	debug int

	// bgpAugment is used to decide if ASN information from netflow packets should be used
	bgpAugment bool
}

// New creates and starts a new `NetflowServer` instance
func New(listenAddr string, numReaders int, bgpAugment bool, debug int) *NetflowServer {
	nfs := &NetflowServer{
		debug:      debug,
		tmplCache:  newTemplateCache(),
		Output:     make(chan *netflow.Flow),
		bgpAugment: bgpAugment,
	}

	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		panic(fmt.Sprintf("ResolveUDPAddr: %v", err))
	}

	con, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(fmt.Sprintf("Listen: %v", err))
	}

	// Create goroutines that read netflow packet and process it
	for i := 0; i < numReaders; i++ {
		go func(num int) {
			nfs.packetWorker(num, con)
		}(i)
	}

	return nfs
}

// packetWorker reads netflow packet from socket and handsoff processing to processFlowSets()
func (nfs *NetflowServer) packetWorker(identity int, conn *net.UDPConn) {
	buffer := make([]byte, 8960)
	for {
		length, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			glog.Errorf("Error reading from socket: %v", err)
			continue
		}
		atomic.AddUint64(&stats.GlobalStats.Packets, 1)

		remote.IP = remote.IP.To4()
		if remote.IP == nil {
			glog.Errorf("Received IPv6 packet. Dropped.")
			continue
		}

		nfs.processPacket(remote.IP, buffer[:length])
	}
}

// processPacket takes a raw netflow packet, send it to the decoder, updates template cache
// (if there are templates in the packet) and passes the decoded packet over to processFlowSets()
func (nfs *NetflowServer) processPacket(remote net.IP, buffer []byte) {
	length := len(buffer)
	packet, err := nf9.Decode(buffer[:length], remote)
	if err != nil {
		glog.Errorf("nf9packet.Decode: %v", err)
		return
	}

	nfs.updateTemplateCache(remote, packet)
	nfs.processFlowSets(remote, packet.Header.SourceID, packet.DataFlowSets(), int64(packet.Header.UnixSecs), packet)
}

// processFlowSets iterates over flowSets and calls processFlowSet() for each flow set
func (nfs *NetflowServer) processFlowSets(remote net.IP, sourceID uint32, flowSets []*nf9.FlowSet, ts int64, packet *nf9.Packet) {
	addr := remote.String()
	keyParts := make([]string, 3, 3)
	for _, set := range flowSets {
		template := nfs.tmplCache.get(convert.Uint32(remote), sourceID, set.Header.FlowSetID)

		if template == nil {
			templateKey := makeTemplateKey(addr, sourceID, set.Header.FlowSetID, keyParts)
			if nfs.debug > 0 {
				glog.Warningf("Template for given FlowSet not found: %s", templateKey)
			}
			continue
		}

		records := template.DecodeFlowSet(*set)
		if records == nil {
			glog.Warning("Error decoding FlowSet")
			continue
		}
		nfs.processFlowSet(template, records, remote, ts, packet)
	}
}

// process generates Flow elements from records and pushes them into the `receiver` channel
func (nfs *NetflowServer) processFlowSet(template *nf9.TemplateRecords, records []nf9.FlowDataRecord, agent net.IP, ts int64, packet *nf9.Packet) {
	fm := generateFieldMap(template)

	for _, r := range records {
		if fm.family == 4 {
			atomic.AddUint64(&stats.GlobalStats.Flows4, 1)
		} else if fm.family == 6 {
			atomic.AddUint64(&stats.GlobalStats.Flows6, 1)
		} else {
			glog.Warning("Unknown address family")
			continue
		}

		var fl netflow.Flow
		fl.Router = agent
		fl.Timestamp = ts
		fl.Family = uint32(fm.family)
		fl.Packets = convert.Uint32(r.Values[fm.packets])
		fl.Size = uint64(convert.Uint32(r.Values[fm.size]))
		fl.Protocol = convert.Uint32(r.Values[fm.protocol])
		fl.IntIn = convert.Uint32(r.Values[fm.intIn])
		fl.IntOut = convert.Uint32(r.Values[fm.intOut])
		fl.SrcPort = convert.Uint32(r.Values[fm.srcPort])
		fl.DstPort = convert.Uint32(r.Values[fm.dstPort])
		fl.SrcAddr = convert.Reverse(r.Values[fm.srcAddr])
		fl.DstAddr = convert.Reverse(r.Values[fm.dstAddr])
		fl.NextHop = convert.Reverse(r.Values[fm.nextHop])

		if !nfs.bgpAugment {
			fl.SrcAs = convert.Uint32(r.Values[fm.srcAsn])
			fl.DstAs = convert.Uint32(r.Values[fm.dstAsn])
		}

		/*if debug > 2 {
			fl.Packet = packet
			fl.Template = template.Header.TemplateID
			Dump(&fl)
		}*/

		nfs.Output <- &fl
	}
}

// Dump dumps a flow on the screen
func Dump(fl *netflow.Flow) {
	fmt.Printf("--------------------------------\n")
	fmt.Printf("Flow dump:\n")
	fmt.Printf("Router: %d\n", fl.Router)
	fmt.Printf("Family: %d\n", fl.Family)
	fmt.Printf("SrcAddr: %s\n", net.IP(fl.SrcAddr).String())
	fmt.Printf("DstAddr: %s\n", net.IP(fl.DstAddr).String())
	fmt.Printf("Protocol: %d\n", fl.Protocol)
	fmt.Printf("NextHop: %s\n", net.IP(fl.NextHop).String())
	fmt.Printf("IntIn: %d\n", fl.IntIn)
	fmt.Printf("IntOut: %d\n", fl.IntOut)
	fmt.Printf("Packets: %d\n", fl.Packets)
	fmt.Printf("Bytes: %d\n", fl.Size)
	fmt.Printf("--------------------------------\n")
}

// DumpTemplate dumps a template on the screen
func DumpTemplate(tmpl *nf9.TemplateRecords) {
	fmt.Printf("Template %d\n", tmpl.Header.TemplateID)
	for rec, i := range tmpl.Records {
		fmt.Printf("%d: %v\n", i, rec)
	}
}

// generateFieldMap processes a TemplateRecord and populates a fieldMap accordingly
// the FieldMap can then be used to read fields from a flow
func generateFieldMap(template *nf9.TemplateRecords) *fieldMap {
	var fm fieldMap
	i := -1
	for _, f := range template.Records {
		i++

		switch f.Type {
		case nf9.IPv4SrcAddr:
			fm.srcAddr = i
			fm.family = 4
		case nf9.IPv6SrcAddr:
			fm.srcAddr = i
			fm.family = 6
		case nf9.IPv4DstAddr:
			fm.dstAddr = i
		case nf9.IPv6DstAddr:
			fm.dstAddr = i
		case nf9.InBytes:
			fm.size = i
		case nf9.Protocol:
			fm.protocol = i
		case nf9.InPkts:
			fm.packets = i
		case nf9.InputSnmp:
			fm.intIn = i
		case nf9.OutputSnmp:
			fm.intOut = i
		case nf9.IPv4NextHop:
			fm.nextHop = i
		case nf9.IPv6NextHop:
			fm.nextHop = i
		case nf9.L4SrcPort:
			fm.srcPort = i
		case nf9.L4DstPort:
			fm.dstPort = i
		case nf9.SrcAs:
			fm.srcAsn = i
		case nf9.DstAs:
			fm.dstAsn = i
		}
	}
	return &fm
}

// updateTemplateCache updates the template cache
func (nfs *NetflowServer) updateTemplateCache(remote net.IP, p *nf9.Packet) {
	templRecs := p.GetTemplateRecords()
	for _, tr := range templRecs {
		nfs.tmplCache.set(convert.Uint32(remote), tr.Packet.Header.SourceID, tr.Header.TemplateID, *tr)
	}
}

// makeTemplateKey creates a string of the 3 tuple router address, source id and template id
func makeTemplateKey(addr string, sourceID uint32, templateID uint16, keyParts []string) string {
	keyParts[0] = addr
	keyParts[1] = strconv.Itoa(int(sourceID))
	keyParts[2] = strconv.Itoa(int(templateID))
	return strings.Join(keyParts, "|")
}

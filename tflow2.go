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

// Package main is the main package of tflow2
package main

import (
	"flag"
	"runtime"
	"sync"

	"github.com/google/tflow2/annotator"
	"github.com/google/tflow2/database"
	"github.com/google/tflow2/frontend"
	"github.com/google/tflow2/ifserver"
	"github.com/google/tflow2/netflow"
	"github.com/google/tflow2/nfserver"
	"github.com/google/tflow2/stats"
)

var (
	nfAddr        = flag.String("netflow", ":2055", "Address to use to receive netflow packets")
	ipfixAddr     = flag.String("ipfix", ":4739", "Address to use to receive ipfix packets")
	aggregation   = flag.Int64("aggregation", 60, "Time to groups flows together into one data point")
	maxAge        = flag.Int64("maxage", 1800, "Maximum age of saved flows")
	web           = flag.String("web", ":4444", "Address to use for web service")
	birdSock      = flag.String("birdsock", "/var/run/bird/bird.ctl", "Unix domain socket to communicate with BIRD")
	birdSock6     = flag.String("birdsock6", "/var/run/bird/bird6.ctl", "Unix domain socket to communicate with BIRD6")
	bgpAugment    = flag.Bool("bgp", true, "Use BIRD to augment BGP flow information")
	protoNums     = flag.String("protonums", "protocol_numbers.csv", "CSV file to read protocol definitions from")
	sockReaders   = flag.Int("sockreaders", 24, "Num of go routines reading and parsing netflow packets")
	channelBuffer = flag.Int("channelbuffer", 1024, "Size of buffer for channels")
	dbAddWorkers  = flag.Int("dbaddworkers", 24, "Number of workers adding flows into database")
	nAggr         = flag.Int("numaggr", 12, "Number of flow aggregator workers")
	samplerate    = flag.Int("samplerate", 1, "Samplerate of routers")
	debugLevel    = flag.Int("debug", 0, "Debug level, 0: none, 1: +shows if we are receiving flows we are lacking templates for, 2: -, 3: +dump all packets on screen")
	compLevel     = flag.Int("comp", 6, "gzip compression level for data storage on disk")
	dataDir       = flag.String("data", "./data", "Path to store long term flow logs")
	anonymize     = flag.Bool("anonymize", false, "Replace IP addresses with NULL before dumping flows to disk")
)

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())
	stats.Init()

	nfs := nfserver.New(*nfAddr, *sockReaders, *bgpAugment, *debugLevel)

	ifs := ifserver.New(*ipfixAddr, *sockReaders, *bgpAugment, *debugLevel)

	chans := make([]chan *netflow.Flow, 0)
	chans = append(chans, nfs.Output)
	chans = append(chans, ifs.Output)

	flowDB := database.New(*aggregation, *maxAge, *dbAddWorkers, *samplerate, *debugLevel, *compLevel, *dataDir, *anonymize)

	annotator.New(chans, flowDB.Input, *nAggr, *aggregation, *bgpAugment, *birdSock, *birdSock6)

	frontend.New(*web, *protoNums, flowDB)

	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}

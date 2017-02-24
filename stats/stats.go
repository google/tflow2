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

// Package stats provides central statistics about tflow2
package stats

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Stats represents statistics of this program that are to be exported via /varz
type Stats struct {
	StartTime     int64
	Flows4        uint64
	Flows6        uint64
	Packets       uint64
	Queries       uint64
	BirdCacheHits uint64
	BirdCacheMiss uint64
	FlowPackets   uint64
	FlowBytes     uint64
}

// GlobalStats is instance of `Stats` to keep stats of this program
var GlobalStats Stats

// Init initilizes this module
func Init() {
	GlobalStats.StartTime = time.Now().Unix()
}

// Varz is used to serve HTTP requests /varz and send the statistics to a client in borgmon/prometheus compatible format
func Varz(w http.ResponseWriter) {
	now := time.Now().Unix()
	fmt.Fprintf(w, "netflow_collector_uptime %d\n", now-GlobalStats.StartTime)
	fmt.Fprintf(w, "netflow_collector_flows4 %d\n", atomic.LoadUint64(&GlobalStats.Flows4))
	fmt.Fprintf(w, "netflow_collector_flows6 %d\n", atomic.LoadUint64(&GlobalStats.Flows6))
	fmt.Fprintf(w, "netflow_collector_netflow_packets %d\n", atomic.LoadUint64(&GlobalStats.Packets))
	fmt.Fprintf(w, "netflow_collector_queries %d\n", atomic.LoadUint64(&GlobalStats.Queries))
	fmt.Fprintf(w, "netflow_collector_bird_cache_hits %d\n", atomic.LoadUint64(&GlobalStats.BirdCacheHits))
	fmt.Fprintf(w, "netflow_collector_bird_cache_miss %d\n", atomic.LoadUint64(&GlobalStats.BirdCacheMiss))
	fmt.Fprintf(w, "netflow_collector_packets %d\n", atomic.LoadUint64(&GlobalStats.FlowPackets))
	fmt.Fprintf(w, "netflow_collector_bytes %d\n", atomic.LoadUint64(&GlobalStats.FlowBytes))
}

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

// Package frontend provides services via HTTP
package frontend

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof" // Needed for profiling only
	"net/url"
	"os"
	"regexp"
	"strings"
	"tflow2/database"
	"tflow2/stats"

	"github.com/golang/glog"
)

// Frontend represents the web interface
type Frontend struct {
	protocols map[string]string
	indexHTML string
	flowDB    *database.FlowDatabase
}

// New creates a new `Frontend`
func New(addr string, protoNumsFilename string, fdb *database.FlowDatabase) *Frontend {
	fe := &Frontend{
		flowDB: fdb,
	}
	fe.populateProtocols(protoNumsFilename)
	fe.populateIndexHTML()
	http.HandleFunc("/", fe.httpHandler)
	go http.ListenAndServe(addr, nil)
	return fe
}

// populateIndexHTML copies tflow2.html into indexHTML variable
func (fe *Frontend) populateIndexHTML() {
	html, err := ioutil.ReadFile("tflow2.html")
	if err != nil {
		glog.Errorf("Unable to read tflow2.html: %v", err)
		return
	}

	fe.indexHTML = string(html)
}

func (fe *Frontend) populateProtocols(protoNumsFilename string) {
	f, err := os.Open(protoNumsFilename)
	if err != nil {
		glog.Errorf("Couldn't open protoNumsFile: %v\n", err)
		return
	}
	r := csv.NewReader(bufio.NewReader(f))
	fe.protocols = make(map[string]string)
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}

		ok, err := regexp.Match("^[0-9]{1,3}$", []byte(record[0]))
		if err != nil {
			fmt.Printf("Regex: %v\n", err)
			continue
		}
		if ok {
			fe.protocols[record[0]] = record[1]
		}
	}
}

func (fe *Frontend) httpHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	parts := strings.Split(r.URL.Path, "?")
	path := parts[0]
	switch path {
	case "/":
		fe.indexHandler(w, r)
	case "/query":
		fe.queryHandler(w, r)
	case "/varz":
		stats.Varz(w)
	case "/protocols":
		fe.getProtocols(w, r)
	case "/routers":
		fileHandler(w, r, "routers.json")
	case "/tflow2.css":
		fileHandler(w, r, "tflow2.css")
	case "/tflow2.js":
		fileHandler(w, r, "tflow2.js")
	}
}

func (fe *Frontend) getProtocols(w http.ResponseWriter, r *http.Request) {
	output, err := json.Marshal(fe.protocols)
	if err != nil {
		glog.Warningf("Unable to marshal: %v", err)
		http.Error(w, "Unable to marshal data", 500)
	}
	fmt.Fprintf(w, "%s", output)
}

func fileHandler(w http.ResponseWriter, r *http.Request, filename string) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		glog.Warningf("Unable to read file: %v", err)
		http.Error(w, "Unable to read file", 404)
	}
	fmt.Fprintf(w, "%s", string(content))
}

func (fe *Frontend) indexHandler(w http.ResponseWriter, r *http.Request) {
	query := "{}"
	for _, p := range strings.Split(r.URL.RawQuery, "&") {
		parts := strings.SplitN(p, "=", 2)
		if len(parts) == 0 {
			glog.Warningf("query was empty")
			http.Error(w, "query was empty", 400)
			continue
		}
		param := parts[0]
		value := ""
		if len(parts) == 2 {
			value = parts[1]
		}

		if param == "query" {
			var err error
			query, err = url.QueryUnescape(value)
			if err != nil {
				glog.Warningf("unable to decode URL parameter query")
				http.Error(w, "unable to decode URL parameter query", 503)
			}
		}
	}

	output := strings.Replace(fe.indexHTML, "VAR_QUERY", query, -1)
	fmt.Fprintf(w, output)
}

func (fe *Frontend) queryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	q := ""
	for _, p := range strings.Split(r.URL.RawQuery, "&") {
		parts := strings.SplitN(p, "=", 2)
		param := parts[0]
		value := ""
		if len(parts) > 1 {
			value = parts[1]
		}

		if param == "q" {
			var err error
			q, err = url.QueryUnescape(value)
			if err != nil {
				glog.Warningf("Unable to unescape query: %v", err)
				http.Error(w, "Unable to unescape query", 400)
			}
		}
	}

	result, err := fe.flowDB.RunQuery(q)
	if err != nil {
		glog.Errorf("Query failed: %v", err)
		http.Error(w, "Query failed", 500)
	}

	fe.printResult(w, result)
}

func (fe *Frontend) printResult(w http.ResponseWriter, result [][]string) {
	rows := len(result)
	if rows == 0 {
		return
	}
	columns := len(result[0])

	fmt.Fprintf(w, "[\n")
	fmt.Fprintf(w, "[ ")
	// Send header of table to client
	for i, val := range result[0] {
		if i < columns-1 {
			fmt.Fprintf(w, "\"%s\", ", string(val))
			continue
		}
		fmt.Fprintf(w, "\"%s\"", string(val))
	}
	if rows == 1 {
		fmt.Fprintf(w, "]\n")
		return
	}
	fmt.Fprintf(w, "],\n")

	for i, row := range result[1:] {
		fmt.Fprintf(w, "[ ")
		for j, column := range row {
			if j == 0 {
				fmt.Fprintf(w, "\"%s\", ", string(column))
				continue
			}
			if j < columns-1 {
				fmt.Fprintf(w, "%s, ", string(column))
				continue
			}
			fmt.Fprintf(w, "%s", string(column))
		}
		if i < rows-2 {
			fmt.Fprintf(w, "],\n")
			continue
		}
		fmt.Fprintf(w, "]\n")
	}
	fmt.Fprintf(w, "]")
}

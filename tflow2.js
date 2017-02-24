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

var query;
var protocols;
var availableProtocols = [];
var rtrs;
var routers = [];
var interfaces = [];
const OpEqual = 0;
const OpUnequal = 1;
const OpSmaller = 2;
const OpGreater = 3;
const FieldTimestamp = 0;
const FieldRouter = 1;
const FieldSrcAddr = 2;
const FieldDstAddr = 3;
const FieldProtocol = 4;
const FieldIntIn = 5;
const FieldIntOut = 6;
const FieldNextHop = 7;
const FieldSrcAs = 8;
const FieldDstAs = 9;
const FieldNextHopAs = 10;
const FieldSrcPfx = 11;
const FieldDstPfx = 12;
const FieldSrcPort = 13;
const FieldDstPort = 14;
const fields = {
        "Router": 1,
        "SrcAddr": 2,
        "DstAddr": 3,
        "Protocol": 4,
        "IntIn": 5,
        "IntOut": 6,
        "NextHop": 7,
        "SrcAsn": 8,
        "DstAsn": 9,
        "NextHopAsn": 10,
        "SrcPfx": 11,
        "DstPfx": 12,
        "SrcPort": 13,
        "DstPort": 14,
};
const fieldById = {
    "1": "Router",
    "2": "SrcAddr",
    "3": "DstAddr",
    "4": "Protocol",
    "5": "IntIn",
    "6": "IntOut",
    "7": "NextHop",
    "8": "SrcAsn",
    "9": "DstAsn",
    "10": "NextHopAsn",
    "11": "SrcPfx",
    "12": "DstPfx",
    "13": "SrcPort",
    "14": "DstPort"
};

var bdfields = [
        "SrcAddr", "DstAddr", "Protocol", "IntIn", "IntOut", "NextHop", "SrcAsn", "DstAsn",
        "NextHopAsn", "SrcPfx", "DstPfx", "SrcPort", "DstPort" ];

function drawChart() {
    var query = $("#query").val();
    if (query == "" || query == "{}") {
        return;
    }

    var url = "/query?q=" + encodeURI(query)
    console.log(url);
    $.get(url, function(rdata) {
        console.log(rdata);
        d = [];
        d = JSON.parse(rdata);
        data = google.visualization.arrayToDataTable(d);

        var options = {
            isStacked: true,
            title: 'NetFlow bps of top flows',
            hAxis: {
                title: 'Time',
                titleTextStyle: {
                    color: '#333'
                }
            },
            vAxis: {
                minValue: 0
            }
        };

        var chart = new google.visualization.AreaChart(document.getElementById('chart_div'));
        chart.draw(data, options);
    });
}

function populateForm() {
    var q = $("#query").val();
    if (q == "" || q == "{}") {
        return;
    }

    q = JSON.parse(q);
    $("#topn").val(q.TopN);
    for (var c in q['Cond']) {
        var fieldNum = q['Cond'][c]['Field'];
        var fieldName = fieldById[fieldNum];
        var operand = q['Cond'][c]['Operand'];
        if (fieldNum == FieldRouter) {
            operand = getRouterById(operand);
            if (operand == null) {
                return;
            }
        } else if (fieldNum == FieldIntIn || fieldNum == FieldIntOut) {
            operand = getInterfaceById($("#Router").val(), operand);
            if (operand == null) {
                return;
            }
        } else if (fieldNum == FieldProtocol) {
            operand = protocols[operand];
            if (operand == null) {
                return;
            }
        }

        $("#" + fieldName).val(operand);
    }
    loadInterfaceOptions();

    for (var f in q['Breakdown']) {
        $("#bd" + f).prop( "checked", true );
    }
}

function loadInterfaceOptions() {
    var rtr = $("#Router").val();
    interfaces = [];
    if (!rtrs[rtr]) {
        return;
    }
    for (var k in rtrs[rtr]["interfaces"]) {
        interfaces.push(rtrs[rtr]["interfaces"][k]);
    }

    $("#IntIn").autocomplete({
        source: interfaces
    });

    $("#IntOut").autocomplete({
        source: interfaces
    });
}

function loadProtocols() {
    return $.get("/protocols", function(rdata) {
        protocols = JSON.parse(rdata);
        for (var k in protocols) {
            availableProtocols.push(protocols[k]);
        }

        $("#Protocol").autocomplete({
            source: availableProtocols
        });
    });
}

function loadRouters() {
    return $.get("/routers", function(rdata) {
        rtrs = JSON.parse(rdata);
        for (var k in rtrs) {
            routers.push(k);
        }

        $("#Router").autocomplete({
            source: routers,
            change: function() {
                loadInterfaceOptions();
            }
        });
    });
}

$(document).ready(function() {
    var start = new Date(((new Date() / 1000) - 900)* 1000).toISOString().substr(0, 16)
    if ($("#TimeStart").val() == "") {
        $("#TimeStart").val(start);
    }

    var end = new Date().toISOString().substr(0, 16)
    if ($("#TimeEnd").val() == "") {
        $("#TimeEnd").val(end);
    }

    $.when(loadRouters(), loadProtocols()).done(function() {
        $("#Router").on('input', function() {
            loadInterfaceOptions();
        })
        populateForm();
    })

    $("#submit").on('click', submitQuery);

    google.charts.load('current', {
        'packages': ['corechart']
    });
    google.charts.setOnLoadCallback(drawChart);
});

function getProtocolId(name) {
    for (var k in protocols) {
        if (protocols[k] == name) {
            return k;
        }
    }
    return null;
}

function getIntId(rtr, name) {
    if (!rtrs[rtr]) {
        return null;
    }
    for (var k in rtrs[rtr]['interfaces']) {
        if (rtrs[rtr]['interfaces'][k] == name) {
            return k;
        }
    }
    return null;
}

function getRouterById(id) {
    for (var k in rtrs) {
        if (rtrs[k]['id'] == id) {
            return k;
        }
    }
    return null;
}

function getInterfaceById(router, id) {
    return rtrs[router]['interfaces'][id];
}

function submitQuery() {
    var query = {
        Cond: [],
        Breakdown: {},
        TopN: parseInt($("#topn").val())
    };

    console.log($("#TimeStart").val());
    var start = new Date($("#TimeStart").val());
    var end = new Date($("#TimeEnd").val());
    start = Math.round(start.getTime() / 1000);
    end = Math.round(end.getTime() / 1000);
    query['Cond'].push({
        Field: FieldTimestamp,
        Operator: OpGreater,
        Operand: start + ""
    });
    query['Cond'].push({
        Field: FieldTimestamp,
        Operator: OpSmaller,
        Operand: end + ""
    });

    for (var k in fields) {
        tmp = $("#" + k).val();
        if (tmp == "") {
            continue;
        }
        if (k == "Router") {
            tmp = rtrs[tmp]['id'];
        } else if (k == "IntIn" || k == "IntOut") {
            tmp = getIntId($("#Router").val(), tmp)
            if (tmp == null) {
                return;
            }
        } else if (k == "Protocol") {
            tmp = getProtocolId(tmp);
            if (tmp == null) {
                return;
            }
        }
        query['Cond'].push({
            Field: fields[k],
            Operator: OpEqual,
            Operand: tmp + ""
        });
    }

    for (var i = 0; i < bdfields.length; i++) {
        if (!$("#bd" + bdfields[i]).prop('checked')) {
            continue;
        }
        query['Breakdown'][bdfields[i]] = true;
    }

    console.log(query);
    $("#query").val(JSON.stringify(query));
    $("#form").submit();
}
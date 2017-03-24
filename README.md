# tflow2

tflow2 is an in memory netflow version 9 analyzer.
It is designed for fast arbitrary queries.

*This software is a work in progress and makes no API stability promises.*

## Usage

Quick install with `go get -u github.com/google/tflow2`
and `go build github.com/google/tflow2`
or download a pre-built binary from the
[releases page](https://github.com/google/tflow2/releases).

The release binaries have an additional command, `tflow2 -version`,
which reports the release version.

Once you start the main binary it will start reading netflow version 9 packets
on port 2055 UDP and IPFIX packets on port 4739 on all interfaces.
For user interaction it starts a webserver on port 4444 TCP on all interfaces. 

The webinterface allows you to run queries against the collected data.
Start time and router are mandatory criteria. If you don't provide any of
these you will always receive an empty result.

### Command line arguments
-aggregation=int 

  This is the time window in seconds used for aggregation of flows

-alsologtostderr

  Will send logs to stderr on top

-bgp=true/false

  tflow will connect to BIRD and BIRD6 unix domain sockets to augment flows
  with prefix and autonomous system information. This is useful in case your
  routers exported netflow data is lacking these. This is the case for example
  if you use the ipt-NETFLOW on Linux.

  BIRD needs a BGP session to each router that is emitting flow packets.
  The protocol needs to be named like this: "nf_x_y_z_a" with x_y_z_a being the
  source IP address of flow packets, e.g. nf_185_66_194_0

-birdSock=path

  This is the path to the unix domain socket to talk to BIRD

-birdSock6=path

  This is the path to the unix domain socket to talk to BIRD6

-channelBuffer=int

  This is the amount of elements that any channel within the program can buffer.

-dbaddworkers=int

  This is the amount of workers that are used to add flows into the in memory
  database.

-debug=int

  Debug level. 1 will give you some more information. 2 is not in use at
  the moment. 3 will dump every single received netflow packet on the screen.

-log_backtrace_at

  when logging hits line file:N, emit a stack trace (default :0)

-log_dir

  If non-empty, write log files in this directory

-logtostderr

  log to standard error instead of files

-maxage=int

  Maximum age of flow data to keep in memory. Choose this parameter wisely or you
  will run out of memory. Experience shows that 500k flows need about 50G of RAM.

-netflow=addr

  Address to use to receive netflow packets (default ":2055") via UDP

-ipfix=addr

  Address to use to receive IPFIX packets (default ":4739") via UDP

--protonums=path

  CSV file to read protocol definitions from (default "protocol_numbers.csv").
  This is needed for suggestions in the web interface.

-samplerate=int

  Samplerate of your routers. This is used to deviate real packet and volume rates
  in case you use sampling.

-sockreaders=int

  Num of go routines reading and parsing netflow packets (default 24)

-stderrthreshold

  logs at or above this threshold go to stderr

-v value

  log level for V logs

-vmodule value

  comma-separated list of pattern=N settings for file-filtered logging

-web=addr

  Address to use for web service (default ":4444")

## Limitations

This software currently only supports receiving netflow packets over IPv4.
Please be aware this software is not platform indipendent. It will only work
on little endian machines (such as x86)

## License

(c) Google, 2017. Licensed under [Apache-2](LICENSE) license.

This is not an official Google product.

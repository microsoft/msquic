#! /usr/bin/env bash

# Set up the routing needed for the simulation
/setup.sh

if [ -n "$TESTCASE" ]; then
    case "$TESTCASE" in
    # TODO: add supported test cases here
    "versionnegotiation"|"handshake"|"transfer"|"retry"|"resumption"|\
    "multiconnect"|"zerortt"|"chacha20")
        ;;
    *)
        exit 127
        ;;
    esac
fi

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

# Start LTTng log collection.
mkdir /log
lttng -q create msquiclive --live
lttng enable-event --userspace CLOG_*
lttng start
babeltrace -i lttng-live net://localhost
HOST=`hostname`
babeltrace --names all -i lttng-live net://localhost/host/$HOST/msquiclive \
    | clog2text_lttng -s clog.sidecar --showTimestamp --showCpuInfo \
    > /log/quic.log &

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    cd /downloads || exit

    # TODO: add client support
    # I am not sure if the msquic codebase has an h09 client?
    exit 127

elif [ "$ROLE" == "server" ]; then
    case "$TESTCASE" in
    "retry")
        SERVER_PARAMS="-retry:1 $SERVER_PARAMS"
        ;;
    *)
        ;;
    esac

    quicinteropserver ${SERVER_PARAMS} -root:/www -listen:* -port:443 \
        -file:/server.crt -key:/server.key 2>&1
fi

#! /usr/bin/env bash

# Set up the routing needed for the simulation
/setup.sh

if [ -n "$TESTCASE" ]; then
    case "$TESTCASE" in
    # TODO: add supported test cases here
    "versionnegotiation"|"handshake"|"transfer"|"retry"|"resumption"|\
    "multiconnect")
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

# Start LTTng live streaming.
lttng -q create msquiclive --live 1000
lttng enable-event --userspace CLOG_*
lttng add-context --userspace --type=vpid --type=vtid
lttng start
babeltrace -i lttng-live net://localhost
babeltrace --names all -i lttng-live net://localhost/host/`hostname`/msquiclive \
    | stdbuf -i0 -o0 clog2text_lttng -s clog.sidecar --t --c > /logs/quic.log &

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    cd /downloads || exit

    case "$TESTCASE" in
    "resumption")
        CLIENT_PARAMS="-test:R $CLIENT_PARAMS"
        ;;
    "versionnegotiation")
        CLIENT_PARAMS="-test:V $CLIENT_PARAMS"
        ;;
    "handshake")
        CLIENT_PARAMS="-test:H $CLIENT_PARAMS"
        ;;
    "handshakecorruption")
        CLIENT_PARAMS="-test:H $CLIENT_PARAMS"
        ;;
    "handshakeloss")
        CLIENT_PARAMS="-test:H $CLIENT_PARAMS"
        ;;
    "zerortt")
        CLIENT_PARAMS="-test:Z $CLIENT_PARAMS"
        ;;
    *)
        CLIENT_PARAMS="-test:D $CLIENT_PARAMS"
        ;;
    esac

    for REQ in $REQUESTS; do
        FILE=`echo $REQ | cut -f4 -d'/'`
        quicinterop ${CLIENT_PARAMS} -urlpath "/"$FILE -custom:server -port:443
    done
    # Wait for the logs to flush to disk.
    sleep 2

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

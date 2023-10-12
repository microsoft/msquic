#! /usr/bin/env bash

# Set up the routing needed for the simulation
/setup.sh

if [ -n "$TESTCASE" ]; then
    case "$TESTCASE" in
    # TODO: add supported test cases here
    "versionnegotiation"|"handshake"|"resumption"|"zerortt"|"transfer"|"retry"|"multiconnect"|"keyupdate"|"chacha20"|"v2")
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
#echo "Starting LTTng logging..."
#lttng -q create msquiclive --live 1000
#lttng enable-event --userspace CLOG_*
#lttng add-context --userspace --type=vpid --type=vtid
#lttng start
#babeltrace -i lttng-live net://localhost
#babeltrace --names all -i lttng-live net://localhost/host/`hostname`/msquiclive \
#    | stdbuf -i0 -o0 clog2text_lttng -s clog.sidecar --t --c > /logs/quic.log &

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    cd /downloads || exit

    CLIENT_PARAMS="-sslkeylogfile:$SSLKEYLOGFILE $CLIENT_PARAMS"

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
    "transfer")
        CLIENT_PARAMS="-test:D -timeout:50000 $CLIENT_PARAMS"
        ;;
    "multiconnect")
        CLIENT_PARAMS="-test:D -timeout:25000 $CLIENT_PARAMS"
        ;;
    "zerortt")
        CLIENT_PARAMS="-test:Z $CLIENT_PARAMS"
        ;;
    "keyupdate")
        CLIENT_PARAMS="-test:U $CLIENT_PARAMS"
        ;;
    "chacha20")
        CLIENT_PARAMS="-test:A $CLIENT_PARAMS"
        ;;
    "v2")
        CLIENT_PARAMS="-test:2 $CLIENT_PARAMS"
        ;;
    *)
        CLIENT_PARAMS="-test:D $CLIENT_PARAMS"
        ;;
    esac

    # Figure out the server name from the first request. This assumes all URLS
    # point to the same server.
    REQS=($REQUESTS)
    REQ=${REQS[0]}
    SERVER=$(echo $REQ | cut -d'/' -f3 | cut -d':' -f1)
    echo "Connecting to $SERVER"
    echo "Client params (before files):$CLIENT_PARAMS"

    if [ "$TESTCASE" == "multiconnect" ]; then
        for REQ in $REQUESTS; do
            quicinterop ${CLIENT_PARAMS} -custom:$SERVER -port:443 -urls:"$REQ"
        done
    else
        # FIXME: there doesn't seem to be a way to specify to use /certs/ca.pem
        # for certificate verification
        quicinterop ${CLIENT_PARAMS} -custom:$SERVER -port:443 -urls:${REQUESTS[@]}
    fi
    # Wait for the logs to flush to disk.
    sleep 5

    echo "Client complete."

elif [ "$ROLE" == "server" ]; then
    case "$TESTCASE" in
    "retry")
        SERVER_PARAMS="-retry:1 $SERVER_PARAMS"
        ;;
    "v2")
        SERVER_PARAMS="-enablevne:1 $SERVER_PARAMS"
        ;;
    *)
        ;;
    esac

    quicinteropserver ${SERVER_PARAMS} -root:/www -listen:* -port:443 \
        -file:/certs/cert.pem -key:/certs/priv.key -noexit &
    wait

    echo "Server complete."
fi

echo "Script complete."

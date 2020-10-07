#! /usr/bin/env bash

# Set up the routing needed for the simulation
/setup.sh

if [ -n "$TESTCASE" ]; then
    case "$TESTCASE" in
    # TODO: add supported test cases here
    "versionnegotiation"|"handshake"|"transfer"|"retry"|"multiconnect"|"keyupdate")
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

# Setup and start LTTng logging.
echo "Starting LTTng logging..."
mkdir /logs/lttng
lttng -q create msquic -o=/logs/lttng
lttng enable-event --userspace CLOG_*
lttng add-context --userspace --type=vpid --type=vtid
lttng start

# Trap TERM and EXIT signals to stop LTTng logging and convert.
QUIT=0
trap StopLTTng TERM EXIT
function StopLTTng() {
    echo "Trap fired."
    if [ "$QUIT" -ne 1 ]; then
        echo "Stopping LTTng logging..."
        lttng stop msquic
        babeltrace --names all /logs/lttng/* > /logs/babeltrace.txt
        rm -rf /logs/lttng
        clog2text_lttng -i /logs/babeltrace.txt -s /clog.sidecar --t --c -o /logs/quic.log
        rm /logs/babeltrace.txt
        echo "LTTng logging stopped and converted."
        QUIT=1
    fi
    echo "Exiting script..."
    exit
}

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
    *)
        CLIENT_PARAMS="-test:D $CLIENT_PARAMS"
        ;;
    esac

    if [ "$TESTCASE" == "multiconnect" ]; then
        for REQ in $REQUESTS; do
            quicinterop ${CLIENT_PARAMS} -custom:server -port:443 -urls:"$REQ" -version:-16777187
        done
    else
        # FIXME: there doesn't seem to be a way to specify to use /certs/ca.pem
        # for certificate verification
        quicinterop ${CLIENT_PARAMS} -custom:server -port:443 -urls:${REQUESTS[@]} -version:-16777187
    fi

    echo "Client complete."

elif [ "$ROLE" == "server" ]; then
    case "$TESTCASE" in
    "retry")
        SERVER_PARAMS="-retry:1 $SERVER_PARAMS"
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

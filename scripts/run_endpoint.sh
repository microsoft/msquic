#! /usr/bin/env bash

# Set up the routing needed for the simulation
/setup.sh

if [ -n "$TESTCASE" ]; then
    case "$TESTCASE" in
    # TODO: add supported test cases here
    "versionnegotiation"|"handshake"|"transfer"|"retry"|"resumption"|\
    "multiconnect"|"ecn"|"keyupdate")
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

quit=0

# Setup and start LTTng logging.
echo "Starting LTTng logging..."
mkdir /logs/lttng
lttng -q create msquic -o=/logs/lttng
lttng enable-event --userspace CLOG_*
lttng add-context --userspace --type=vpid --type=vtid
lttng start

# Trap SIGTERM and exit signals to stop LTTng logging and convert.
trap StopLTTng SIGTERM exit
function StopLTTng() {
  echo "Stopping LTTng logging..."
  lttng stop msquic
  babeltrace --name all /logs/lttng/* > /logs/babeltrace.txt
  clog2text_lttng -i /logs/babeltrace.txt -s clog.sidecar --t --c -o /logs/quic.log
  quit=1
  echo "LTTng logging stopped and converted."
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

    if [ "$TESTCASE" == "multiconnect" ]; then
        for REQ in $REQUESTS; do
            quicinterop ${CLIENT_PARAMS} -custom:server -port:443 -urls:"$REQ" -version:-16777187
        done
    else
        echo "Requests parameter: ${REQUESTS[@]}"
        # FIXME: there doesn't seem to be a way to specify to use /certs/ca.pem
        # for certificate verification
        quicinterop ${CLIENT_PARAMS} -custom:server -port:443 -urls:"${REQUESTS[@]}" -version:-16777187
    fi

elif [ "$ROLE" == "server" ]; then
    case "$TESTCASE" in
    "retry")
        SERVER_PARAMS="-retry:1 $SERVER_PARAMS"
        ;;
    *)
        ;;
    esac

    quicinteropserver ${SERVER_PARAMS} -root:/www -listen:* -port:443 \
        -file:/certs/cert.pem -key:/certs/priv.key &

    # Wait for the trap to execute and set the quit variable.
    echo "Waiting for quit..."
    while [ "$quit" -ne 1 ]; do
        sleep 1
    done
fi

# This is for Linux

lttng destroy msquic 2> /dev/null

dirname="msquic_lttng"
num=`find ./* -maxdepth 0 -name "$dirname*" | wc -l`
mkdir $dirname$num && lttng create msquic -o=./$dirname$num && sessionCreated=$? && lttng enable-event --userspace "CLOG_*" && lttng add-context --userspace --type=vpid --type=vtid && lttng start
if [ $? -eq 0 ]; then
    $*
    lttng stop
fi

if [ $sessionCreated -eq 0 ]; then
    lttng destroy msquic
fi

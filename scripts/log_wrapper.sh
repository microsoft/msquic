# This is for Linux

lttng destroy msquic 2> /dev/null

dirprefix="msquic_lttng"
num=`find ./* -maxdepth 0 -name "$dirprefix*" | wc -l`
dirname=$dirprefix$num
mkdir -p $dirname/data && lttng create msquic -o=./$dirname/data && sessionCreated=$? && lttng enable-event --userspace "CLOG_*" && lttng add-context --userspace --type=vpid --type=vtid && lttng start
if [ $? -eq 0 ]; then
    $*
    lttng stop
fi

if [ $sessionCreated -eq 0 ]; then
    lttng destroy msquic

    babeltrace --names all $dirname/data > $dirname/quic.babel.txt
    ./submodules/clog/src/clog2text/clog2text_lttng/bin/Release/net6.0/publish/clog2text_lttng -i $dirname/quic.babel.txt -s ./src/manifest/clog.sidecar -o $dirname/quic.log --showTimestamp --showCpuInfo
fi

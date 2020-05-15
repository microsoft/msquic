#
#  Copyright (c) Microsoft Corporation.
#  Licensed under the MIT License.
#

import sys
import csv
import matplotlib.pyplot as plt
import matplotlib.ticker as plticker

#
# Usage:
#
#  netsh trace start overwrite=yes report=dis correlation=dis traceFile=quic.etl maxSize=1024 provider={ff15e657-4f26-570e-88ab-0796b258d11c} level=0x5 keywords=0xC0000100
#  (Run scenario)
#  netsh trace stop
#  (Find connection id of interest ("--id N") with "quicetw quic.etl --conn_list")
#  quicetw quic.etl --csv --conn_tput --id N --reso 10 > quic.csv
#  python quic_plot_conn_tput.py quic.csv
#
# Optional param: pass --nofc to remove FC windows from the plots (they typically dwarf other values).
#

#
# Install/update the following dependencies first to use:
#
#  python -m pip install -U pip
#  python -m pip install -U matplotlib
#

timeMs = []
txMbps = []
rxMbps = []
rttMs = []
congEvent = []
inFlight = []
cwnd = []
fcStream = []
fcConn = []

# ms,TxMbps,RxMbps,RttMs,CongEvents,InFlight,Cwnd,TxBufBytes,FlowAvailStrm,FlowAvailConn,SsThresh,CubicK,CubicWindowMax,StrmSndWnd

with open(sys.argv[1]) as csvfile:
    csvReader = csv.reader(csvfile)
    csvReader.__next__() # Skip column header
    for row in csvReader:
        # Stop processing the file once we don't have all the columns.
        if len(row) < 13:
            break
        timeMs.append(float(row[0]))
        txMbps.append(float(row[1]))
        rxMbps.append(float(row[2]))
        rttMs.append(float(row[3]))
        congEvent.append(int(row[4]))
        inFlight.append(float(row[5]) / 1000)
        cwnd.append(float(row[6]) / 1000)
        fcStream.append(float(row[8]) / 1000)
        fcConn.append(float(row[9]) / 1000)

fig = plt.figure()
heights = [2, 6, 1, 2]
spec = fig.add_gridspec(4, 1, height_ratios=heights)
fig.subplots_adjust(left=0.05, bottom=0.05, right=0.98, top=0.96, wspace=0.01, hspace=0.05)

axs = fig.add_subplot(spec[0,0])
axs.set_title('Connection Throughput', fontsize=20)
data1, = axs.plot(timeMs, txMbps, label="TX")
data2, = axs.plot(timeMs, rxMbps, label="RX")
plt.legend(handles=[data1, data2], loc='upper right')
axs.set_xticks([])
axs.yaxis.set_major_locator(plticker.MaxNLocator())
axs.set_ylabel('Mbps', fontsize=14)
axs.margins(x=0, y=0)

axs = fig.add_subplot(spec[1,0])
data1, = axs.plot(timeMs, inFlight, label="InFlight")
data2, = axs.plot(timeMs, cwnd, label="Cwnd")
if ("--nofc" in sys.argv):
    plt.legend(handles=[data1, data2], loc='upper right')
else:
    data3, = axs.plot(timeMs, fcStream, label="FcStream")
    data4, = axs.plot(timeMs, fcConn, label="FcConn")
    plt.legend(handles=[data1, data2, data3, data4], loc='upper right')
axs.set_xticks([])
axs.yaxis.set_major_locator(plticker.MaxNLocator())
axs.set_ylabel('KB', fontsize=14)
axs.margins(x=0, y=0)

axs = fig.add_subplot(spec[2,0])
data, = axs.plot(timeMs, congEvent, label="Congestion")
plt.legend(handles=[data], loc='upper right')
axs.yaxis.set_major_locator(plticker.MaxNLocator())
axs.set_xticks([])
axs.set_yticks([])
axs.margins(x=0, y=0)

axs = fig.add_subplot(spec[3,0])
data, = axs.plot(timeMs, rttMs, label="RTT")
plt.legend(handles=[data], loc='upper right')
axs.xaxis.set_major_locator(plticker.MaxNLocator())
axs.yaxis.set_major_locator(plticker.MaxNLocator())
axs.set_xlabel('ms', fontsize=14)
axs.set_ylabel('ms', fontsize=14)
axs.margins(x=0, y=0)

mng = plt.get_current_fig_manager()
mng.window.state('zoomed')
plt.legend()
plt.show()

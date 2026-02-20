#!/bin/bash
# plot.sh — Run verified & unverified benchmarks and generate gnuplot charts.
#
# Usage:
#   ./plot.sh [iterations]          # default: 200
#   ./plot.sh 500                   # more iterations for stable results

set -e
cd "$(dirname "$0")"

ITERS="${1:-200}"
DAT="bench.dat"

rm -f "$DAT"

echo "=== Running verified benchmark ($ITERS iterations) ==="
./bench_recv_buffer "$ITERS" --gnuplot "$DAT" --label verified

if [ -x ./bench_recv_buffer_orig ]; then
    echo ""
    echo "=== Running unverified benchmark ($ITERS iterations) ==="
    ./bench_recv_buffer_orig "$ITERS" --gnuplot "$DAT" --label unverified
else
    echo ""
    echo "WARNING: bench_recv_buffer_orig not found, running verified again as placeholder"
    ./bench_recv_buffer "$ITERS" --gnuplot "$DAT" --label unverified
fi

echo ""
echo "=== Generating plots ==="

gnuplot <<'GNUPLOT'
set terminal pngcairo size 900,500 enhanced font 'Arial,11'
set style data linespoints
set xtics rotate by -25
set grid ytics
set key top right
set yrange [0:*]

set output 'throughput.png'
set title 'Write Throughput — Verified vs Unverified CircularBuffer'
set ylabel 'Write Throughput (MB/s)'
plot 'bench.dat' index 0 using 2:xtic(1) title 'verified' lw 2 pt 7 ps 1.2, \
     'bench.dat' index 1 using 2:xtic(1) title 'unverified' lw 2 pt 5 ps 1.2

set output 'ops.png'
set title 'Write Ops/s — Verified vs Unverified CircularBuffer'
set ylabel 'Write ops/s'
plot 'bench.dat' index 0 using 3:xtic(1) title 'verified' lw 2 pt 7 ps 1.2, \
     'bench.dat' index 1 using 3:xtic(1) title 'unverified' lw 2 pt 5 ps 1.2

set output 'latency.png'
set title 'Total Time — Verified vs Unverified CircularBuffer'
set ylabel 'Time (ms)'
plot 'bench.dat' index 0 using 6:xtic(1) title 'verified' lw 2 pt 7 ps 1.2, \
     'bench.dat' index 1 using 6:xtic(1) title 'unverified' lw 2 pt 5 ps 1.2
GNUPLOT

echo "Generated: throughput.png  ops.png  latency.png"

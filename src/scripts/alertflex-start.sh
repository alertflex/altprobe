echo "clean nids redis db"
redis-cli ltrim altprobe_nids -1 0
echo "clean metrics redis db"
redis-cli ltrim altprobe_metrics -1 0
echo "clean hids redis db"
redis-cli ltrim altprobe_hids -1 0
altprobe start

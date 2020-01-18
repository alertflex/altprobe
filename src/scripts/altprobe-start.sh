echo "clean nids redis db"
redis-cli ltrim altprobe_nids -1 0
echo "clean crs redis db"
redis-cli ltrim altprobe_crs -1 0
echo "clean misc redis db"
redis-cli ltrim altprobe_misc -1 0
echo "clean hids redis db"
redis-cli ltrim altprobe_hids -1 0
echo "clean waf redis db"
redis-cli ltrim altprobe_waf -1 0
echo "clean packetbeat redis db"
redis-cli ltrim altprobe_packets -1 0
altprobe start

apt-get update

apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev  libnss3-dev \
libnspr4-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 \
libdaemon-dev libmysqld-dev libconfig-dev libboost-all-dev libmagic-dev \
libjansson-dev libjansson4 libhiredis-dev pkg-config make git unzip

ldconfig

apt-get -y install libzmq3-dev
wget http://download.zeromq.org/czmq-2.2.0.tar.gz
tar xfz czmq-2.2.0.tar.gz
cd czmq-2.2.0
./configure
make all -j
make install
cd ..

cd altprobe
make
make install
cd ..

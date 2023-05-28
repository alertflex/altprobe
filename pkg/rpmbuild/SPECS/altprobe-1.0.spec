Name:           altprobe
Version:        1.0
Release:        3%{?dist}
Summary:        Alertflex collector

License:        Apache License 2.0
# URL:
# Source0:        altprobe-1.0.tar.gz
BuildArch:      x86_64

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# BuildRequires:
# Requires:

%description
Alertflex collector

# %prep
%setup -q


# %build
#%configure
#make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
install -d -m 0755 $RPM_BUILD_ROOT/etc/altprobe
install -m 0755 $RPM_SOURCE_DIR/altprobe.yaml $RPM_BUILD_ROOT/etc/altprobe/altprobe.yaml
install -m 0755 $RPM_SOURCE_DIR/filters.json $RPM_BUILD_ROOT/etc/altprobe/filters.json
install -d -m 0755 $RPM_BUILD_ROOT/etc/altprobe/scripts
install -m 0755 $RPM_SOURCE_DIR/scripts/kube-hunter.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/kube-hunter.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/zap.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/zap.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/nmap.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/nmap.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/nuclei.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/nuclei.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/nikto.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/nikto.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/semgrep.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/semgrep.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/cloudsploit.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/cloudsploit.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/sonarqube.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/sonarqube.sh
install -d -m 0755 $RPM_BUILD_ROOT/usr/sbin
install -m 0755 $RPM_SOURCE_DIR/altprobe $RPM_BUILD_ROOT/usr/sbin/altprobe
install -m 0755 $RPM_SOURCE_DIR/scripts/altprobe-restart $RPM_BUILD_ROOT/usr/sbin/altprobe-restart
install -m 0755 $RPM_SOURCE_DIR/scripts/altprobe-start $RPM_BUILD_ROOT/usr/sbin/altprobe-start
install -m 0755 $RPM_SOURCE_DIR/scripts/altprobe-redis-start $RPM_BUILD_ROOT/usr/sbin/altprobe-redis-start
install -m 0755 $RPM_SOURCE_DIR/scripts/altprobe-status $RPM_BUILD_ROOT/usr/sbin/altprobe-status
install -m 0755 $RPM_SOURCE_DIR/scripts/altprobe-stop $RPM_BUILD_ROOT/usr/sbin/altprobe-stop
install -d -m 0755 $RPM_BUILD_ROOT/usr/local/lib
install -m 0755 $RPM_SOURCE_DIR/libactivemq-cpp.so.20 $RPM_BUILD_ROOT/usr/local/lib/libactivemq-cpp.so.20
install -m 0755 $RPM_SOURCE_DIR/libkubernetes.so $RPM_BUILD_ROOT/usr/local/lib/libkubernetes.so
install -m 0755 $RPM_SOURCE_DIR/libwebsockets.so.18 $RPM_BUILD_ROOT/usr/local/lib/libwebsockets.so.18
install -m 0755 $RPM_SOURCE_DIR/libyaml.so $RPM_BUILD_ROOT/usr/local/lib/libyaml.so
install -m 0755 $RPM_SOURCE_DIR/libcurl.so.4.8.0 $RPM_BUILD_ROOT/usr/local/lib/libcurl.so.4.8.0
install -m 0755 $RPM_SOURCE_DIR/libhiredis.so $RPM_BUILD_ROOT/usr/local/lib/libhiredis.so

%files

%defattr(-,root,root,-)

/etc/altprobe/altprobe.yaml
/etc/altprobe/filters.json
/etc/altprobe/scripts/kube-hunter.sh
/etc/altprobe/scripts/zap.sh
/etc/altprobe/scripts/nmap.sh
/etc/altprobe/scripts/nuclei.sh
/etc/altprobe/scripts/nikto.sh
/etc/altprobe/scripts/semgrep.sh
/etc/altprobe/scripts/cloudsploit.sh
/etc/altprobe/scripts/sonarqube.sh
/usr/sbin/altprobe
/usr/sbin/altprobe-restart
/usr/sbin/altprobe-start
/usr/sbin/altprobe-redis-start
/usr/sbin/altprobe-status
/usr/sbin/altprobe-stop
/usr/local/lib/libactivemq-cpp.so.20
/usr/local/lib/libkubernetes.so
/usr/local/lib/libwebsockets.so.18
/usr/local/lib/libyaml.so
/usr/local/lib/libcurl.so.4.8.0
/usr/local/lib/libhiredis.so

%changelog

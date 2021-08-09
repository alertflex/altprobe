Name:           altprobe
Version:        1.0
Release:        1%{?dist}
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
install -m 0755 $RPM_SOURCE_DIR/scripts/restart-falco.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/restart-falco.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/restart-modsec.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/restart-modsec.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/restart-suri.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/restart-suri.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/restart-wazuh.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/restart-wazuh.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/rulesup-falco.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/rulesup-falco.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/rulesup-modsec.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/rulesup-modsec.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/rulesup-suri.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/rulesup-suri.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/rulesup-wazuh.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/rulesup-wazuh.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/dependency-check.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/dependency-check.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/docker-bench.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/docker-bench.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/kube-bench.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/kube-bench.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/kube-hunter.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/kube-hunter.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/sonarqube.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/sonarqube.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/nikto.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/nikto.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/nmap.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/nmap.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/trivy.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/trivy.sh
install -m 0755 $RPM_SOURCE_DIR/scripts/zap.sh $RPM_BUILD_ROOT/etc/altprobe/scripts/zap.sh
install -d -m 0755 $RPM_BUILD_ROOT/usr/sbin
install -m 0755 $RPM_SOURCE_DIR/altprobe $RPM_BUILD_ROOT/usr/sbin/altprobe
install -m 0755 $RPM_SOURCE_DIR/scripts/altprobe-restart $RPM_BUILD_ROOT/usr/sbin/altprobe-restart
install -m 0755 $RPM_SOURCE_DIR/scripts/altprobe-start $RPM_BUILD_ROOT/usr/sbin/altprobe-start
install -m 0755 $RPM_SOURCE_DIR/scripts/altprobe-status $RPM_BUILD_ROOT/usr/sbin/altprobe-status
install -m 0755 $RPM_SOURCE_DIR/scripts/altprobe-stop $RPM_BUILD_ROOT/usr/sbin/altprobe-stop
install -d -m 0755 $RPM_BUILD_ROOT/usr/lib
install -m 0755 $RPM_SOURCE_DIR/libactivemq-cpp.so.20 $RPM_BUILD_ROOT/usr/lib/libactivemq-cpp.so.20


%files

%defattr(-,root,root,-)

/etc/altprobe/altprobe.yaml
/etc/altprobe/filters.json
/etc/altprobe/scripts/restart-falco.sh
/etc/altprobe/scripts/restart-modsec.sh
/etc/altprobe/scripts/restart-suri.sh
/etc/altprobe/scripts/restart-wazuh.sh
/etc/altprobe/scripts/rulesup-falco.sh
/etc/altprobe/scripts/rulesup-modsec.sh
/etc/altprobe/scripts/rulesup-suri.sh
/etc/altprobe/scripts/rulesup-wazuh.sh
/etc/altprobe/scripts/dependency-check.sh
/etc/altprobe/scripts/docker-bench.sh
/etc/altprobe/scripts/kube-bench.sh
/etc/altprobe/scripts/kube-hunter.sh
/etc/altprobe/scripts/nikto.sh
/etc/altprobe/scripts/nmap.sh
/etc/altprobe/scripts/sonarqube.sh
/etc/altprobe/scripts/trivy.sh
/etc/altprobe/scripts/zap.sh
/usr/sbin/altprobe
/usr/sbin/altprobe-restart
/usr/sbin/altprobe-start
/usr/sbin/altprobe-status
/usr/sbin/altprobe-stop
/usr/lib/libactivemq-cpp.so.20

%changelog

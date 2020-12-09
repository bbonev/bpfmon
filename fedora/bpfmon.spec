Name:           bpfmon
Version:        2.49
Release:        1%{?dist}
Summary:        Traffic monitor for BPF expression/iptables rule

License:        GPLv2+
URL:            https://github.com/bbonev/bpfmon/
Source0:        %{url}releases/download/v%{version}/bpfmon-%{version}.tar.xz
Source1:        %{url}releases/download/v%{version}/bpfmon-%{version}.tar.xz.asc
Source2:        https://raw.githubusercontent.com/bbonev/bpfmon/v%{version}/debian/upstream/signing-key.asc

BuildRequires:  gcc
BuildRequires:  gnupg2
BuildRequires:  make
BuildRequires:  pkgconfig(libpcap)
BuildRequires:  pkgconfig(yascreen)

%description
While tcpdump shows what packets are going through the
network, bpfmon will show how much in terms
of bytes per second and packets per second in a
nice pseudo-graphical terminal interface.

bpfmon also supports monitoring an iptables rule that
is selected by command line option or selected from a
menu.

%global _hardened_build 1

%prep
%{gpgverify} --keyring='%{SOURCE2}' --signature='%{SOURCE1}' --data='%{SOURCE0}'
%autosetup

%build
%set_build_flags
NO_FLTO=1 %make_build PREFIX=%{_usr} STRIP=: bpfmon

%install
V=1 STRIP=: %make_install PREFIX=%{_usr}
install -TD -m 0644 bpfmon.8 $RPM_BUILD_ROOT/%{_mandir}/man8/bpfmon.8

%files
%license LICENSE
%{_sbindir}/bpfmon
%{_mandir}/man8/bpfmon.8*

%changelog
* Sun Dec 6 2020 Boian Bonev <bbonev@ipacct.com> - 2.49-1
- Initial packaging for Fedora

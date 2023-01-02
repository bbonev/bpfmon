Name:           bpfmon
Version:        2.50
Release:        4%{?dist}
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
* Mon Jan 2 2023 Boian Bonev <bbonev@ipacct.com> - 2.50-4
- Rebuilt for yascreen soname bump

* Wed Jul 20 2022 Fedora Release Engineering <releng@fedoraproject.org> - 2.50-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild

* Wed Jan 19 2022 Fedora Release Engineering <releng@fedoraproject.org> - 2.50-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild

* Tue Sep 21 2021 Boian Bonev <bbonev@ipacct.com> - 2.50-1
- New version 2.50

* Wed Jul 21 2021 Fedora Release Engineering <releng@fedoraproject.org> - 2.49-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild

* Tue Jan 26 2021 Fedora Release Engineering <releng@fedoraproject.org> - 2.49-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

* Sun Dec 6 2020 Boian Bonev <bbonev@ipacct.com> - 2.49-1
- Initial packaging for Fedora

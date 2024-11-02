Name:           bpfmon
Version:        2.53
Release:        1%{?dist}
Summary:        Traffic monitor for BPF expression/iptables rule

License:        GPL-2.0-or-later
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
* Sat Nov 2 2024 Boian Bonev <bbonev@ipacct.com> - 2.53-1
- New version 2.53

* Wed Jul 17 2024 Fedora Release Engineering <releng@fedoraproject.org> - 2.52-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_41_Mass_Rebuild

* Tue Jan 23 2024 Fedora Release Engineering <releng@fedoraproject.org> - 2.52-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild

* Fri Jan 19 2024 Fedora Release Engineering <releng@fedoraproject.org> - 2.52-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild

* Sun Aug 13 2023 Boian Bonev <bbonev@ipacct.com> - 2.52-1
- New version 2.52

* Wed Jul 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 2.51-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild

* Tue Feb 14 2023 Boian Bonev <bbonev@ipacct.com> - 2.51-4
- SPDX migration

* Sun Feb 5 2023 Boian Bonev <bbonev@ipacct.com> - 2.51-3
- Rebuilt for yascreen 1.96

* Wed Jan 18 2023 Fedora Release Engineering <releng@fedoraproject.org> - 2.51-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild

* Tue Jan 3 2023 Boian Bonev <bbonev@ipacct.com> - 2.51-1
- New version 2.51

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

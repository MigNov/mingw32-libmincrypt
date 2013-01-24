Name:		mingw32-libmincrypt
Version:	0.0.5
Release:	1%{?dist}%{?extra_release}
Summary:	Library form of minCrypt crypto-algorithm implementation for Windows
Source:		http://www.migsoft.net/projects/mincrypt/mingw32-libmincrypt-%{version}.tar.gz

Group:		Development/Libraries
License:	LGPLv2+
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root
Requires:	mingw32-gcc

%define		debug_package	%{nil}

%description
Windows port of library for minCrypt minimal encryption/decryption system

%prep
%setup -q -n mingw32-libmincrypt-%{version}

%build
%configure
make %{?_smp_mflags}

%install
mkdir -p %{buildroot}/%{_libdir}
mkdir -p %{buildroot}/%{_bindir}
mkdir -p %{buildroot}/%{_includedir}
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE README
%{_bindir}/mincrypt.exe
%{_libdir}/mincrypt.dll
%{_libdir}/libmincrypt.a
%{_includedir}/mincrypt.h

%changelog
* Thu Mar 15 2012 Michal Novotny <mignov@gmail.com> - 0.0.5:
- Fix asymmetric key generation algorithm to generate random initialization vectors

* Tue Dec 27 2011 Michal Novotny <mignov@gmail.com> - 0.0.4:
- Split minCrypt project into minCrypt binary and libminCrypt library

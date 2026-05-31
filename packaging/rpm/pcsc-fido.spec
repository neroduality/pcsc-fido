# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Reference RPM spec for metadata and manual rpmbuild.
# Release packages are built with CPack (`make package`); scriptlets live only in
# packaging/scripts/{postinst,postrm,prerm} and are embedded or %include'd below.

Name:           pcsc-fido
Version:        0.1.0
Release:        1%{?dist}
Summary:        Middleware bridging PC/SC NFC FIDO to browser WebAuthn (daemon side)
License:        Apache-2.0
BuildRequires:  cmake >= 3.20
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  pkgconfig(libpcsclite)
BuildRequires:  systemd-rpm-macros
Requires:       pcsc-lite
Requires:       pcsc-lite-libs
Requires:       pcsc-lite-ccid
Requires:       systemd
Requires:       udev
Requires:       polkit

%description
Daemon-side middleware between Linux browsers and the PC/SC stack: exposes a
virtual FIDO HID authenticator over UHID and relays CTAP/U2F requests to an NFC
FIDO card / NFC enabled security key through pcscd and a CCID-class reader.

Upstream release packages are built natively for amd64 and arm64, and
cross-compiled for armhf, ppc64el, riscv64, and s390x.

%prep
%autosetup -n pcsc-fido-%{version}

%build
%cmake
%cmake_build

%check
%ctest

%install
%cmake_install

%files
%license LICENSE
%{_datadir}/doc/pcsc-fido/INSTALLATION.md
%{_datadir}/doc/pcsc-fido/NOTICE
%{_bindir}/pcsc-fido
%{_libdir}/pcsc-fido/ensure-pcsc-fido-user.sh
%{_udevrulesdir}/70-pcsc-fido.rules
%{_unitdir}/pcsc-fido.service
%{_libdir}/modules-load.d/pcsc-fido-uhid.conf
%{_presetdir}/60-pcsc-fido.preset
%{_sysusersdir}/pcsc-fido.conf
%{_datadir}/polkit-1/rules.d/50-pcsc-fido.rules

%pre
%sysusers_create %{_sysusersdir}/pcsc-fido.conf

%post
%include ../scripts/postinst

%preun
%include ../scripts/prerm

%postun
%include ../scripts/postrm

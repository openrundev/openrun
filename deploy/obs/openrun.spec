#
# spec file for package openrun
#
# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0
#

%global git_commit 910b57f
%global debug_package %{nil}

Name:           openrun
Version:        0.18.3
Release:        0
Summary:        Declarative web app deployment platform
License:        Apache-2.0
URL:            https://openrun.dev/
Source0:        openrun-%{version}.tar.gz
Source1:        openrun.sysusers
BuildRequires:  systemd-rpm-macros
%if 0%{?suse_version}
BuildRequires:  go >= 1.26
BuildRequires:  sysuser-tools
%else
BuildRequires:  golang >= 1.26
%endif
%{?systemd_requires}
%{?sysusers_requires_compat}

%description
OpenRun is an open source alternative to Google Cloud Run and AWS App
Runner. It provides declarative, GitOps based deployment of web apps
and containerized services with built-in TLS, OAuth/OIDC based access
controls and app lifecycle management.

%prep
%autosetup

%build
export CGO_ENABLED=0
export GOTOOLCHAIN=local
go build -mod=vendor -trimpath \
    -ldflags "-w -X github.com/openrundev/openrun/internal/types.gitCommit=%{git_commit} -X github.com/openrundev/openrun/internal/types.gitVersion=%{version}" \
    -o openrun ./cmd/openrun
%if 0%{?suse_version}
%sysusers_generate_pre %{SOURCE1} openrun openrun.conf
%endif

%install
install -D -m0755 openrun %{buildroot}%{_bindir}/openrun
# systemd unit comes from the source tree so packaging cannot drift from
# deploy/init/openrun.service (also used by deploy/setup_systemd.sh)
install -D -m0644 deploy/init/openrun.service %{buildroot}%{_unitdir}/openrun.service
install -D -m0644 %{SOURCE1} %{buildroot}%{_sysusersdir}/openrun.conf
install -d -m0750 %{buildroot}%{_sharedstatedir}/openrun

%if 0%{?suse_version}
%pre -f openrun.pre
%service_add_pre openrun.service
%else
%pre
%sysusers_create_compat %{SOURCE1}
%endif

%post
if [ ! -f %{_sharedstatedir}/openrun/openrun.toml ]; then
    echo "********** Initializing OpenRun 'admin' user password **********"
    runuser -u openrun -- %{_bindir}/openrun password \
        > %{_sharedstatedir}/openrun/openrun.toml || :
    chmod 0600 %{_sharedstatedir}/openrun/openrun.toml || :
    chown openrun:openrun %{_sharedstatedir}/openrun/openrun.toml || :
    echo "********** Save the password shown above ************************"
fi
%if 0%{?suse_version}
%service_add_post openrun.service
%else
%systemd_post openrun.service
%endif

%preun
%if 0%{?suse_version}
%service_del_preun openrun.service
%else
%systemd_preun openrun.service
%endif

%postun
%if 0%{?suse_version}
%service_del_postun openrun.service
%else
%systemd_postun_with_restart openrun.service
%endif

%files
%license LICENSE
%doc README.md
%{_bindir}/openrun
%{_unitdir}/openrun.service
%{_sysusersdir}/openrun.conf
%dir %attr(0750,openrun,openrun) %{_sharedstatedir}/openrun
%ghost %attr(0600,openrun,openrun) %{_sharedstatedir}/openrun/openrun.toml

%changelog

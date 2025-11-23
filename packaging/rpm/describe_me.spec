%global debug_package %{nil}
%{!?cargo_features:%global cargo_features cli web config systemd net journald}

Name:           describe-me
Version:        0.3.11
Release:        1%{?dist}
Summary:        Server snapshot & health CLI/dashboard
License:        Apache-2.0
URL:            https://github.com/Max-Perso/describe_me
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  git
BuildRequires:  rust
BuildRequires:  systemd-rpm-macros

Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
describe-me affiche rapidement un état synthétique d'un serveur (CPU, RAM, OS,
uptime, services, sockets, etc.) et peut exposer un tableau de bord web.

%prep
%autosetup -n %{name}-%{version}

%build
export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
export CARGO_TARGET_DIR=target
cargo build --release --locked --features "%{cargo_features}"
cargo build --release --locked --manifest-path plugin-examples/certificates/Cargo.toml

%install
install -Dm755 target/release/describe-me %{buildroot}%{_bindir}/describe-me
install -Dm755 target/release/describe-me-plugin-certificates %{buildroot}/usr/lib/describe_me/plugins/describe-me-plugin-certificates

install -dm755 %{buildroot}%{_sysconfdir}/describe_me
install -Dm644 packaging/config/config.toml %{buildroot}%{_sysconfdir}/describe_me/config.toml

install -dm755 %{buildroot}%{_localstatedir}/lib/describe-me
install -Dm644 packaging/systemd/describe-me.service %{buildroot}%{_unitdir}/describe-me.service

%post
%systemd_post describe-me.service

%preun
%systemd_preun describe-me.service

%postun
%systemd_postun_with_restart describe-me.service

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/describe-me
/usr/lib/describe_me/plugins/describe-me-plugin-certificates
%dir %{_sysconfdir}/describe_me
%config(noreplace) %{_sysconfdir}/describe_me/config.toml
%dir %{_localstatedir}/lib/describe-me
%{_unitdir}/describe-me.service

%changelog
* Sun Nov 23 2025 Maxime Guillemin <guimaxali@gmail.com> - 0.3.11-1
- Bump version to 0.3.0 (sync with Cargo.toml)
* Tue Feb 25 2025 Maxime Guillemin <guimaxali@gmail.com> - 0.2.2-1
- Première version RPM pour describe-me

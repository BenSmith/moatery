%global source_date_epoch_from_changelog 0

Name:           customs
Version:        %(cat %{_sourcedir}/VERSION)
Release:        %{?buildserial:1.%{buildserial}}%{!?buildserial:1}
Summary:        Egress inspector and credential broker for sandboxed workloads

License:        MIT
BuildArch:      noarch

BuildRequires:  python3 >= 3.14
BuildRequires:  openssl
Requires:       python3 >= 3.14
# The command line: the CA and every per-host certificate are openssl
# invocations.
Requires:       openssl >= 3.5
# The container shapes: rules loaded into the workload's netns with nft,
# its traffic carried by pasta.
Recommends:     podman
Recommends:     passt
Recommends:     nftables

%description
customs inspects what a sandboxed workload sends out and brokers the
credentials it uses without the workload holding them. customs-inspect
is a transparent egress inspector with a per-workload CA and an
allow-list; customs-broker attaches the real key to the requests the
inspector hands it; customs-resolve answers the workload's DNS and asks
no one. customs-mint-ca makes the CA, and customs-netns-listen binds
the listeners inside a rootless container's network namespace.

%prep
# Built from a checkout: _sourcedir is the repository root.

%install
# The programs and their modules in one directory, so each finds the
# modules through its own sys.path[0].
install -dm 0755 %{buildroot}%{_libexecdir}/customs
for f in %{_sourcedir}/lib/*.py; do
    install -pm 0644 "$f" %{buildroot}%{_libexecdir}/customs/
done
for f in customs-broker customs-inspect customs-mint-ca \
        customs-netns-listen customs-resolve; do
    install -pm 0755 %{_sourcedir}/libexec/$f \
        %{buildroot}%{_libexecdir}/customs/
done

install -dm 0755 %{buildroot}%{_docdir}/customs
cp -pr %{_sourcedir}/README.md %{_sourcedir}/docs %{_sourcedir}/examples \
    %{buildroot}%{_docdir}/customs/
install -Dpm 0644 %{_sourcedir}/LICENSE \
    %{buildroot}%{_datadir}/licenses/customs/LICENSE

%check
# Every program imports its closure from the installed directory.
for f in customs-broker customs-inspect customs-mint-ca \
        customs-netns-listen customs-resolve; do
    %{buildroot}%{_libexecdir}/customs/$f --help >/dev/null
done

%files
%license %{_datadir}/licenses/customs/LICENSE
%dir %{_libexecdir}/customs
%{_libexecdir}/customs/*.py
%{_libexecdir}/customs/customs-broker
%{_libexecdir}/customs/customs-inspect
%{_libexecdir}/customs/customs-mint-ca
%{_libexecdir}/customs/customs-netns-listen
%{_libexecdir}/customs/customs-resolve
%{_docdir}/customs/

%changelog

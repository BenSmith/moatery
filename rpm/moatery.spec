%global source_date_epoch_from_changelog 0

Name:           moatery
Version:        %(cat %{_sourcedir}/VERSION)
Release:        %{?buildserial:1.%{buildserial}}%{!?buildserial:1}
Summary:        Egress inspector and credential broker for sandboxed workloads

License:        MIT
BuildArch:      noarch

BuildRequires:  python3 >= 3.14
BuildRequires:  python3-rpm-macros
BuildRequires:  openssl
Requires:       python3 >= 3.14
# The package is in this Python's site-packages and no other's.
Requires:       python(abi) = %{python3_version}
# The command line: the CA and every per-host certificate are openssl
# invocations.
Requires:       openssl >= 3.5
# The container placements: rules loaded into the workload's netns with nft,
# its traffic carried by pasta.
Recommends:     podman
Recommends:     passt
Recommends:     nftables
# moathut's completion, which bash-completion loads.
Suggests:       bash-completion

%description
moatery inspects what a sandboxed workload sends out and brokers the
credentials it uses without the workload holding them. moat-inspect
is a transparent egress inspector with a per-workload CA and an
allow-list; moat-broker attaches the real key to the requests the
inspector hands it; moat-resolve answers the workload's DNS and asks
no one. moat-mint-ca makes the CA, and moat-netns-listen binds
the listeners inside a rootless container's network namespace.
moathut runs long-lived, inspected containers for command-line
work, each a quadlet pod with the programs in its namespace.

%prep
# Built from a checkout: _sourcedir is the repository root.

%install
# The package where Python looks, so the programs and anything else may
# import it; the programs in their own directory.
for pkg in moatery moathut; do
    install -dm 0755 %{buildroot}%{python3_sitelib}/$pkg
    for f in %{_sourcedir}/$pkg/*.py; do
        install -pm 0644 "$f" %{buildroot}%{python3_sitelib}/$pkg/
    done
done
install -Dpm 0755 %{_sourcedir}/bin/moathut \
    %{buildroot}%{_bindir}/moathut
install -Dpm 0644 %{_sourcedir}/completions/moathut.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/moathut
install -dm 0755 %{buildroot}%{_libexecdir}/moatery
for f in moat-broker moat-inspect moat-mint-ca \
        moat-netns-listen moat-resolve; do
    install -pm 0755 %{_sourcedir}/libexec/$f \
        %{buildroot}%{_libexecdir}/moatery/
done

install -dm 0755 %{buildroot}%{_docdir}/moatery
cp -pr %{_sourcedir}/README.md %{_sourcedir}/docs %{_sourcedir}/examples \
    %{buildroot}%{_docdir}/moatery/
install -Dpm 0644 %{_sourcedir}/LICENSE \
    %{buildroot}%{_datadir}/licenses/moatery/LICENSE

%check
# Every program imports its closure from the installed package.
for f in moat-broker moat-inspect moat-mint-ca \
        moat-netns-listen moat-resolve; do
    PYTHONPATH=%{buildroot}%{python3_sitelib} \
        %{buildroot}%{_libexecdir}/moatery/$f --help >/dev/null
done
PYTHONPATH=%{buildroot}%{python3_sitelib} \
    %{buildroot}%{_bindir}/moathut --help >/dev/null

%files
%license %{_datadir}/licenses/moatery/LICENSE
%{python3_sitelib}/moatery/
%{python3_sitelib}/moathut/
%{_bindir}/moathut
%{_datadir}/bash-completion/completions/moathut
%dir %{_libexecdir}/moatery
%{_libexecdir}/moatery/moat-broker
%{_libexecdir}/moatery/moat-inspect
%{_libexecdir}/moatery/moat-mint-ca
%{_libexecdir}/moatery/moat-netns-listen
%{_libexecdir}/moatery/moat-resolve
%{_docdir}/moatery/

%changelog

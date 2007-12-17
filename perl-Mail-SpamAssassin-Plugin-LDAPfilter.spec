Summary:	An LDAP-based blacklist engine for SpamAssassin
Name:		perl-Mail-SpamAssassin-Plugin-LDAPfilter
Version:	0.09
Release:	%mkrel 3
License:	Apache License
Group:		Development/Perl
URL:		http://www.ntrg.com/misc/ldapfilter/
Source0:	http://www.ntrg.com/misc/ldapfilter/ldapfilter.cf
Source1:	http://www.ntrg.com/misc/ldapfilter/ldapfilter.pm
Source2:	http://www.ntrg.com/misc/ldapfilter/mailFilter.schema
Source3:	http://www.ntrg.com/misc/ldapfilter/spamAssassinFilter.schema
Requires(pre): rpm-helper
Requires(postun): rpm-helper
Requires(pre):  spamassassin-spamd >= 3.1.1
Requires:	spamassassin-spamd >= 3.1.1
BuildRequires:	perl-doc
BuildArch:	noarch

%description
This plugin checks an LDAP directory for entries and attributes that are
associated with specific message resource, and assigns SpamAssassin scores to
the message according to the values that are returned.

%prep

%setup -q -T -c -n %{name}-%{version}

cp %{SOURCE0} LDAPfilter.cf
cp %{SOURCE1} LDAPfilter.pm
cp %{SOURCE2} .
cp %{SOURCE3} .

# fix path
perl -pi -e "s|ldapfilter\.pm|%{perl_vendorlib}/Mail/SpamAssassin/Plugin/LDAPfilter\.pm|g" LDAPfilter.cf

%build

perldoc LDAPfilter.pm > Mail::SpamAssassin::Plugin::LDAPfilter.3pm

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

install -d %{buildroot}%{_sysconfdir}/mail/spamassassin/
install -d %{buildroot}%{perl_vendorlib}/Mail/SpamAssassin/Plugin
install -d %{buildroot}%{_mandir}/man3

install -m0644 LDAPfilter.cf %{buildroot}%{_sysconfdir}/mail/spamassassin/
install -m0644 LDAPfilter.pm %{buildroot}%{perl_vendorlib}/Mail/SpamAssassin/Plugin/
install -m0644 Mail::SpamAssassin::Plugin::LDAPfilter.3pm %{buildroot}%{_mandir}/man3/

%post
if [ -f %{_var}/lock/subsys/spamd ]; then
    %{_initrddir}/spamd restart 1>&2;
fi
    
%postun
if [ "$1" = "0" ]; then
    if [ -f %{_var}/lock/subsys/spamd ]; then
        %{_initrddir}/spamd restart 1>&2
    fi
fi

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%files
%defattr(644,root,root,755)
%doc mailFilter.schema spamAssassinFilter.schema
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/mail/spamassassin/LDAPfilter.cf
%{perl_vendorlib}/Mail/SpamAssassin/Plugin/LDAPfilter.pm
%{_mandir}/man3/Mail::SpamAssassin::Plugin::LDAPfilter.3pm*
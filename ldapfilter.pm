#
# Mail::SpamAssassin::Plugin::LDAPfilter:
# version 0.09, August 20, 2005
#
# Eric A. Hall, <ehall@ntrg.com>
# http://www.ntrg.com/misc/ldapfilter/
#
# <@LICENSE>
# Copyright 2005 Eric A. Hall <ehall@ntrg.com>
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
# </@LICENSE>
#
# CHANGELOG:
#
# v0.01 -- initial release
# v0.02 -- added eval statements to force timeouts on LDAP searches
# v0.03 -- removed duplicate logout calls on LDAP search errors
# v0.04 -- improved the resource parsing and verification code
# v0.05 -- added code to use LDAP SRV records for initial discovery,
#          consolidated the "ldap_port" and "ldap_ssl_port" variables,
#          further improved the resource verification code
# v0.06 -- added support for checking ftp:, http[s]: and mailto: URIs
# v0.07 -- separated email address verification and normalization,
#          simplified email address parsing routines significantly,
#          added explicit support for the null "<>" email addresses
# v0.08 -- further improved email address verification and normalization,
#          added support for multiple Reply-To addresses (per RFCs)
#          fixed minor bug with permission error and RootDSE queries
#          streamlined LDAP session handling
# v0.09 -- got the LDAP SRV fallback processing to work,
#          moved the login and probe code into sub-functions,
#          re-enabled the reconnect-on-probe-failure code
#

=head1 NAME

Mail::SpamAssassin::Plugin::LDAPfilter - an LDAP-based blacklist engine
for SpamAssassin

=head1 DESCRIPTION

This plugin checks an LDAP directory for entries and attributes that are
associated with specific message resource, and assigns SpamAssassin
scores to the message according to the values that are returned.

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::LDAPfilter ldapfilter.pm

  header LDAP_IP_FROM_BLACK       eval:ldap_ip_from_blacklisted()
  describe LDAP_IP_FROM_BLACK     Checks SMTP client IP for blacklist
  tflags LDAP_IP_FROM_BLACK       net
  score LDAP_IP_FROM_BLACK        50.0

=head1 INTRODUCTION

This plugin was developed for the purpose of being able to store 
blacklist and whitelist data in an LDAP server. It was originally
intended to provide a way to reuse the Postfix LDAP filters inside
SpamAssassin, but has subsequently detoured into becoming a generalized
front-end for LDAP filtering mechanisms in SpamAssassin.

Using this plugin, the author is able to:

=over

=item * blacklist mail from problematic spammers and their providers,

=item * whitelist and lightlist mail from known-good sender networks,

=item * lightlist mailing list traffic (envelope or message addresses),

=item * lightlist mail for postmaster while blacklisting abusive sources,

=item * darklist mail with Reply-To addresses in some freemail domains,

=item * blacklist mail sessions that HELO as one of my network hosts,

=item * implement per-user LDAP filters in user SpamAssassin installs,

=item * ...and more.

=back

Essentially, any domain name, email address, IP subnet (CIDR masking) or
IP octet grouping can be assigned a blacklist, darklist, lightlist or 
whitelist attribute value, with the cumulative set of values determining
the score that is returned to SpamAssassin.

For the author's network, most of this functionality was originally
provided with various Postfix filters, or was provided with static
blacklist and whitelist entries inside SpamAssassin. Both of those
mechanisms are certainly capable of providing important features, but
neither of them worked well enough for the author's purposes. In
particular, Postfix has a very powerful filtering model, but those filters
are not available to SpamAssassin (EG, they have diferent "whitelist"
filtering tools). Meanwhile, the filtering mechanisms in SpamAssassin are
not reusable across machine and account boundaries easily (without using
something like NFS anyway), and don't provide much granularity. Thus,
LDAPfilter was originally designed to makea Postfix LDAP filters available
to SpamAssassin so that they could be shared, but has since been developed
as its own LDAP-based blacklisting tool.

A visual representation of a typical LDAP entry and its associated
attributes is shown below:

     mailFilterName = ietf.org
      |
      +-spamAssassinFilterClient = LIGHTLISTED
      |
      +-spamAssassinFilter822To = LIGHTLISTED

In the example shown above, an email message that was determined to have
been sent by a computer in the "ietf.org" domain (as determined from the
SMTP client reverse-DNS domain name) would match for the "LIGHTLISTED"
score, as would messages with an RFC-822 To: or Cc: header field value
containing "ietf.org". Messages that matched both of those resource-
specific filters would get two LIGHTLISTED scores, which would combine.

Another example is shown below:

    cn=Spammers
      |
      +-mailFilterName = cnchost.com
      |
      +-mailFilterName = mypcclub.net
      |
      +-spamAssassinFilterClient = BLACKLISTED
      |
      +-spamAssassinFilterEnvFrom = BLACKLISTED

In the example shown above, there is a single entry for problematic
spam sources (cn=Spammers), which has multiple mailFilterName attributes
that each identify a known spammer resource (domain names are shown here,
but almost any resource can be used). Hosts that have reverse-DNS domain
names are caught and flagged by the spamAssassinFilterClient attribute,
while email adddresses from the SMTP envelope "MAIL FROM" command are
trapped by the spamAssassinFilterEnvFrom attribute.

Using this model, the author is able to define global entries that are
accessible to all of the front-line SMTP servers, while users are also
able to define additional entries in their personal LDAP views.

=head1 FUNCTIONAL OVERVIEW

When an email message is examined by a version of SpamAssassin that
incorporates this plugin, the data values associated with some of the
message resources will be read (EG, the contents of a From: header),
and LDAP queries for those resources will be generated. If any entries
are found for the resource or one of its delegation parents (such as
the mail-domain from a discovered email address), those entries are
examined to see if they contain any of the user-specified LDAP
attributes. If those attributes exist, the attribute values are also
examined to see if they match with the user-specified matching values.
If that match also succeeds, one or more user-specified SpamAssassin
scores are assigned to the message, with the final score depending on
the number of matches and their user-assigned scores.

There are several important components to this model:

=over

=item Message resources

By default, LDAPfilter parses a message for information that is
commonly used for blacklisting purposes. In particular, it looks for
the IPv4 address and reverse DNS domain name of the SMTP client, the
HELO identifier used in the SMTP session, the email addresses that
were provided in the SMTP envelope ("MAIL FROM" and "RCPT TO"), and
the email addresses that were provided in the RFC-822 message header
(specifically including the From:, Reply-To:, To: and Cc: headers).

The data values for each resource are used to build LDAP searches
for those resources and their delegation parents. These searches are
then submitted to the LDAP server for processing.

Each of the supported resource types can have their type-specific
searches disabled as the operator sees fit, and operators also have
control over the depth of resource recursion that takes place.

Note that LDAPfilter does not currently support IPv6 addresses, but
this is on the author's to-do list. Theoretically, this same model
can also be applied to additional header fields and even body data,
but this potential capability has not been developed upon.

=item LDAP schema

LDAPfilter makes use of several different LDAP attributes, which
can each be manually defined if needed.

In order to ensure efficient searching, LDAPfilter looks for entries
that have a specific naming attribute. By default, the naming
attribute is "mailFilterName", but this can be overridden in the
configuration settings on a global basis, or on a type-specific
basis if you already have entries and attributes that you want to
match against.

When entries are returned for any of the searches, LDAPfilter also
looks to see if there is also a resource-specific attribute assigned
to each entry (for example, searches for email addresses from the
"From:" header field will also be filtered by looking for the
presence of a "spamAssassinFilter822From" attribute by default).
Each of the resource-specific filtering attributes can be defined
in the configuration options if needed.

If the resource-specific attribute is found, its value is read and
compared against the local filtering syntax. The four values that
are used by default are "BLACKLISTED", "DARKLISTED", "LIGHTLISTED"
and "WHITELISTED", but these can also be overridden if needed.

A schema file for LDAPfilter that is suitable for use with OpenLDAP
is available at http://www.ntrg.com/misc/ldapfilter/

Configuration syntax settings for overriding the default LDAP
attributes and values are provided further ahead.

=item SpamAssassin rules and scoring values

The ldapfilter.cf file contains all of the SpamAssassin rules that
define the actual scores which are eventually assigned to each of
the specific matches. By default, each of the resource-specific
searches have four rules, each of which provide a score based on
whether or not the LDAP filter attribute exists with the defined
matching value.

The score for each rule and resource can be adjusted as needed by
changing the relevant score. The deafult for all rules are as
shown above, but it may make sense to change some rules for your
specific environment. For example, it may be useful to assign
different scores for Reply-To: header fields than MAIL-FROM
envelope data which is verified with SPF.

A SpamAssassin rules file for LDAPfilter is available at
http://www.ntrg.com/misc/ldapfilter/

=item Plugin configuration options

There are numerous options that can be defined for LDAPfilter.
Among these options are the ability to override all of the LDAP
attributes and schema, configuration statements that govern the
LDAP session and its related parameters, whether or not sessions
should be maintained across multiple messages, control over the
recursion behavior, and so forth.

LDAPfilter is designed to operate without needing explicit
option statements, but some option definitions are usually
required for basic LDAP connectivity. By default, LDAPfilter
will try to connect to port 389 on localhost, and will try to
perform an anonymous bind, and will also try to use the base DN
returned by the server as the search base. However, this only
works if your instance of SpamAssassin is running on the same
host as your LDAP server and if the anonymous user has read
acccess rights to the attributes. While feasible, these
assumptions are not likely to work in all cases. Furthermore,
there are several performance-boosting configuration statements
that should also be defined, such as defining the search base
for queries to use (thereby preventing the whole tree from being
searched on each query).

A sample configuration file for LDAPfilter is available at
http://www.ntrg.com/misc/ldapfilter/

=back

The specific options are discussed in more detail further ahead
in this document.

=cut

#
# declare the package and necessary modules
#
# NOTE: the Net::LDAP modules are loaded later
#
package Mail::SpamAssassin::Plugin::LDAPfilter;

our $VERSION = "0.09";

#
# make sure Mail::SpamAssassin::Plugin is available
#
eval {require Mail::SpamAssassin::Plugin};

if ($@) {

	dbg ("LDAPfilter\:   Mail::SpamAssassin module " .
		"unavailable ... terminating");

	return 0;
}

use strict;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

#
# register the module
#
sub new {

	#
	# object constructor crap
	#
	my $class = shift;
	my $mailsaobject = shift;

	$class = ref($class) || $class;
	my $self = $class->SUPER::new($mailsaobject);
	bless ($self, $class);

	#
	# ldap session variables
	#
	$self->{ldap_transport} = "ldap";

	$self->{ldap_server} = "";
	$self->{ldap_version} = 3;

	$self->{ldap_port} = "";

	$self->{ldap_ssl_verify} = "none";
	$self->{ldap_ssl_capath} = "/etc/ssl/certs/";

	$self->{ldap_ldapi_path} = "/var/run/slapd/ldapi";

	$self->{ldap_bind_dn} = "";
	$self->{ldap_bind_password} = "";

	$self->{ldap_search_base} = "";
	$self->{ldap_search_scope} = "sub";
	$self->{ldap_search_deref} = "never";

	#
	# ldapfilter toggles and dials
	#
	$self->{search_ip_from} = "on";
	$self->{search_rdns_from} = "on";
	$self->{search_helo_from} = "on";
	$self->{search_env_from} = "on";
	$self->{search_env_to} = "on";
	$self->{search_msg_from} = "on";
	$self->{search_msg_rplyto} = "on";
	$self->{search_msg_tocc} = "on";
	$self->{search_msg_uri} = "on";
	
	$self->{ldap_timeout} = 5;
	$self->{ldap_persistency} = "off";
	$self->{ldap_search_mode} = "batch";

	$self->{env_from_header} = "Return-Path";
	$self->{env_to_header} = "";

	$self->{verify_resources} = "on";
	$self->{recipient_limit} = 10;
	$self->{recipient_filter} = "";
	$self->{uri_limit} = 10;
	$self->{cidr_lookups} = "on";
	$self->{recursion_limit} = 0;

	$self->{search_related_ptr} = "off";
	$self->{search_related_a} = "off";
	$self->{search_related_ns} = "off";
	$self->{search_related_mx} = "off";

	#
	# ldap attribute names
	#
	$self->{ldap_match_attr} = "mailFilterName";
	$self->{ldap_ip_match_attr} = "";
	$self->{ldap_dns_match_attr} = "";
	$self->{ldap_email_match_attr} = "";
	$self->{ldap_uri_match_attr} = "";

	$self->{ldap_ip_from_attr} = "spamAssassinFilterClient";
	$self->{ldap_rdns_from_attr} = "spamAssassinFilterClient";
	$self->{ldap_helo_from_attr} = "spamAssassinFilterHelo";
	$self->{ldap_env_from_attr} = "spamAssassinFilterEnvFrom";
	$self->{ldap_env_to_attr} = "spamAssassinFilterEnvTo";
	$self->{ldap_msg_from_attr} = "spamAssassinFilter822From";
	$self->{ldap_msg_rplyto_attr} = "spamAssassinFilter822RplyTo";
	$self->{ldap_msg_tocc_attr} = "spamAssassinFilter822To";
	$self->{ldap_msg_uri_attr} = "spamAssassinFilter822Uri";

	#
	# ldap attribute values
	#
	$self->{ldap_blacklist_val} = "BLACKLISTED";
	$self->{ldap_darklist_val} = "DARKLISTED";
	$self->{ldap_lightlist_val} = "LIGHTLISTED";
	$self->{ldap_whitelist_val} = "WHITELISTED";

	#
	# register the eval rules
	#
	$self->register_eval_rule("ldap_ip_from_blacklisted");
	$self->register_eval_rule("ldap_ip_from_darklisted");
	$self->register_eval_rule("ldap_ip_from_lightlisted");
	$self->register_eval_rule("ldap_ip_from_whitelisted");

	$self->register_eval_rule("ldap_rdns_from_blacklisted");
	$self->register_eval_rule("ldap_rdns_from_darklisted");
	$self->register_eval_rule("ldap_rdns_from_lightlisted");
	$self->register_eval_rule("ldap_rdns_from_whitelisted");

	$self->register_eval_rule("ldap_helo_from_blacklisted");
	$self->register_eval_rule("ldap_helo_from_darklisted");
	$self->register_eval_rule("ldap_helo_from_lightlisted");
	$self->register_eval_rule("ldap_helo_from_whitelisted");

	$self->register_eval_rule("ldap_env_from_blacklisted");
	$self->register_eval_rule("ldap_env_from_darklisted");
	$self->register_eval_rule("ldap_env_from_lightlisted");
	$self->register_eval_rule("ldap_env_from_whitelisted");

	$self->register_eval_rule("ldap_env_to_blacklisted");
	$self->register_eval_rule("ldap_env_to_darklisted");
	$self->register_eval_rule("ldap_env_to_lightlisted");
	$self->register_eval_rule("ldap_env_to_whitelisted");

	$self->register_eval_rule("ldap_msg_from_blacklisted");
	$self->register_eval_rule("ldap_msg_from_darklisted");
	$self->register_eval_rule("ldap_msg_from_lightlisted");
	$self->register_eval_rule("ldap_msg_from_whitelisted");

	$self->register_eval_rule("ldap_msg_rplyto_blacklisted");
	$self->register_eval_rule("ldap_msg_rplyto_darklisted");
	$self->register_eval_rule("ldap_msg_rplyto_lightlisted");
	$self->register_eval_rule("ldap_msg_rplyto_whitelisted");

	$self->register_eval_rule("ldap_msg_tocc_blacklisted");
	$self->register_eval_rule("ldap_msg_tocc_darklisted");
	$self->register_eval_rule("ldap_msg_tocc_lightlisted");
	$self->register_eval_rule("ldap_msg_tocc_whitelisted");

	$self->register_eval_rule("ldap_msg_uri_blacklisted");
	$self->register_eval_rule("ldap_msg_uri_darklisted");
	$self->register_eval_rule("ldap_msg_uri_lightlisted");
	$self->register_eval_rule("ldap_msg_uri_whitelisted");

	return $self;
}

#
# this gets called as each parameter in the .cf file is encountered.
# note that parameter names are lowercased by the calling function.
#
sub parse_config {

=head1 CONFIGURATION

Configuration options override the default values.

The configuration option statements follow a simple structure of:

    name    value

Option names are case-neutral. Some option values are case-neutral
(eg, the "on|off" toggles), while some of them are not (passwords
and the like).

Option values can be enclosed in single- or double-quotes if needed,
and the quotes will be stripped off when the file is read.

A default configuration file is available at
http://www.ntrg.com/misc/ldapfilter/

WARNING: Do not place this file into the SpamAssassin hierarchy,
since those folders are deleted whenever it is upgraded.

=cut

	#
	# suck down the config object
	#
	my ($self, $config) = @_;

=head2 LDAP Session Options

The session defaults should be fine if (1) your LDAP server can be found
with DNS lookups for the LDAP SRV resource record, (2) anonymous has search
rights, and (3) you are using the bundled LDAP schema. If any of those
assumptions are false, you will need to define the relevant setting(s).

You will probably need to define the ldapfilter_ldap_search_base option,
since the default behavior is to probe for a namingContext attribute in the
rootDSE object. This doesn't always work, and searches from the root of the
tree will be much slower than searches that start in the target container.

Note that DNS lookups for LDAP SRV resource records will not overwrite an
explicit port number setting. This is usually important with LDAP-over-SSL
connections, which tend to use a different port number than the one that is
associated with SRV entries.

    ldapfilter_ldap_transport             ldap  # ldap|ldaps|ldapi

    ldapfilter_ldap_server                ""    # use LDAP SRV data
    ldapfilter_ldap_port                  ""    # use LDAP SRV data
    ldapfilter_ldap_version               3

    ldapfilter_ldap_bind_dn               ""    # use anonymous bind
    ldapfilter_ldap_bind_password         ""    # use anonymous bind

    ldapfilter_ldap_search_base           ""    # use the namingContext
    ldapfilter_ldap_search_scope          sub   # base|one|sub
    ldapfilter_ldap_search_deref          never # never|search|find|always

=cut
	#
	# read and verify ldapfilter_ldap_transport
	#
	if ($config->{key} eq 'ldapfilter_ldap_transport') {

		if ($config->{value} =~ /^[\'\"]?\s*(ldap|ldaps|ldapi)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: " .
				"using \"$1\"");

			$self->{ldap_transport} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"transport; using default value of ".
				"\"$self->{ldap_transport}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_server
	#
	if ($config->{key} eq 'ldapfilter_ldap_server') {

		if (($config->{value} =~ /^[\'\"]?\s*([\w\.\-]+)\s*[\'\"]?$/) &&
			(verify_domain_name($1) == 1)) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_server} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"hostname; using default value of ".
				"\"$self->{ldap_server}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_port
	#
	if ($config->{key} eq 'ldapfilter_ldap_port') {

		if (($config->{value} =~ /^[\'\"]?\s*(\d+?)\s*[\'\"]?$/) &&
			($1 > 0) &&
			($1 < 65536)) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_port} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"port number; using default value of ".
				"\"$self->{ldap_port}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_version
	#
	if ($config->{key} eq 'ldapfilter_ldap_version') {

		if ($config->{value} =~ /^[\'\"]?\s*([2-3])\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_version} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"version number; using default value of ".
				"\"$self->{ldap_version}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_bind_dn
	#
	if ($config->{key} eq 'ldapfilter_ldap_bind_dn') {

		if ($config->{value} =~ /^[\'\"]?\s*(.+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_bind_dn} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"distinguished name; using default value of ".
				"\"$self->{ldap_bind_dn}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_bind_password
	#
	if ($config->{key} eq 'ldapfilter_ldap_bind_password') {

		if ($config->{value} =~ /^[\'\"]?\s*(.*?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"************\"");

			$self->{ldap_bind_password} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"password; using default value of ".
				"\"$self->{ldap_bind_password}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_search_base
	#
	if ($config->{key} eq 'ldapfilter_ldap_search_base') {

		if ($config->{value} =~ /^[\'\"]?\s*(.+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_search_base} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"distinguished name; will probe for ".
				"default naming context");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_scope
	#
	if ($config->{key} eq 'ldapfilter_search_scope') {

		if ($config->{value} =~ /^[\'\"]?\s*(base|one|sub)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_search_scope} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"search scope; using default value of ".
				"\"$self->{ldap_search_scope}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_deref
	#
	if ($config->{key} eq 'ldapfilter_search_deref') {

		if ($config->{value} =~ /^[\'\"]?\s*(never|search|find|always)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_search_deref} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"deref behavior; using default value of ".
				"\"$self->{ldap_search_deref}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

Supported connection methods include "ldaps" (for LDAP-over-SSL security)
and "ldapi" (for LDAP-over-UNIX sockets performance).

LDAPS sessions don't do any certificate validation by default. You shouldn't
need to enable certificate validation unless you plan to use a server that
is not under your direct control, but if you do enable it you may also need
to adjust ldapfilter_ldap_ssl_capath to use your CA certificate store.

    ldapfilter_ldap_ssl_verify            none  # none|optional|require
    ldapfilter_ldap_ssl_capath            /etc/ssl/certs/

=cut

	#
	# read and verify ldapfilter_ldap_ssl_capath
	#
	if ($config->{key} eq 'ldapfilter_ldap_ssl_capath') {

		if ($config->{value} =~ /^[\'\"]?\s*([\/\w\.\-]+)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_ssl_capath} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"pathname; using default value of ".
				"\"$self->{ldap_ssl_capath}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_ssl_verify
	#
	if ($config->{key} eq 'ldapfilter_ldap_ssl_verify') {

		if ($config->{value} =~ /^[\'\"]?\s*(none|optional|require)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_ssl_verify} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"certificate verification level; using default value of ".
				"\"$self->{ldap_ssl_verify}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

If you want to use LDAPI, you will almost certainly need to specify the path
to your local server's UNIX domain socket, since the default is practically
guaranteed to be wrong (don't forget to double-check ACL permissions for the
ldapi socket... mine didn't work).

    ldapfilter_ldap_ldapi_path            /var/run/slapd/ldapi

=cut

	#
	# read and verify ldapfilter_ldap_ldapi_path
	#
	if ($config->{key} eq 'ldapfilter_ldap_ldapi_path') {

		if ($config->{value} =~ /^[\'\"]?\s*([\/\w\.\-]+)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_ldapi_path} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"pathname; using default value of ".
				"\"$self->{ldap_ldapi_path}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

'ldapfilter_ldap_timeout' says how long to wait (in seconds) for an LDAP
operation to succeed before giving up on it. The default values in Net::LDAP
are much higher than the values used here, because we have to consider the
negative impact that timeouts have on SpamAssassin and related processes.
Generally speaking it is better for us to suicide early than to cause
other processes to die by making them wait too long.

    ldapfilter_ldap_timeout               5     # timeout value in seconds

=cut

	#
	# read and verify ldapfilter_ldap_timeout
	#
	if ($config->{key} eq 'ldapfilter_ldap_timeout') {

		if ($config->{value} =~ /^[\'\"]?\s*(\d+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_timeout} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"timeout limit; using default value of ".
				"\"$self->{ldap_timeout}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

'ldapfilter_ldap_persistency' controls whether or not the LDAP session is
killed after the searches complete. Enabling this feature avoids the need to
connect and login for every lookup process, which significantly reduces the 
overall task-completion times. However, this is really only meaningful if
SpamAssassin itself is running in persistent mode (eg, using spamd).

    ldapfilter_ldap_persistency           off   # on|off

=cut

	#
	# read and verify ldapfilter_ldap_persistency
	#
	if ($config->{key} eq 'ldapfilter_ldap_persistency') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_persistency} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{ldap_persistency}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

'ldapfilter_ldap_search_mode' determines whether the resource-specific
searches are performed one-at-a-time or as a batch.  In 'single' mode,
the original resource name and all of its delegation parent names are
searched individually. In 'batch' mode, the resource name and all of its
delegation parent names are combined into a single LDAP search filter,
using the LDAP 'OR' operator. Batch searches avoid some latency delays
and also require fewer network resources, but the queries are harder for
LDAP servers to process than simplistic equality filters.

    ldapfilter_ldap_search_mode           batch # batch|single 

=cut

	#
	# read and verify ldapfilter_ldap_search_mode
	#
	if ($config->{key} eq 'ldapfilter_ldap_search_mode') {

		if ($config->{value} =~ /^[\'\"]?\s*(batch|single)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_search_mode} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{ldap_search_mode}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=head2 LDAP Schema Options

The *_match_attr options are used for name-based matching. By default, all
searches first try to find a match with "(mailFilterName = $resource)", but
you can redefine that global attribute if you want. You can also define
the three major resource-type (IP address, hostname, and email address),
matching attributes too, and those will be used in the appropriate places.
For example, if you define ldapfilter_ldap_email_match_attr to "mail"
(thus reusing the "mail" attribute from the inetOrgPerson objectclass),
searches for email addresses will use "(mail = $resource)", while the rest
of the searches will still use whatever has been assinged to the global
matching attribute (assuming they are also undefined, of course). Note that
the heuristic matching uses simple regular expression analysis (digits and
dots are likely to be IP addresses...), and this can fail in a couple of
places (ie, an email address without an @domain qualifier looks just like
a domain name), so consider this to be experimental.

    ldapfilter_ldap_match_attr            mailFilterName
    ldapfilter_ldap_ip_match_attr         ""
    ldapfilter_ldap_dns_match_attr        ""
    ldapfilter_ldap_email_match_attr      ""

=cut
	#
	# read and verify ldapfilter_ldap_match_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_match_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_match_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_match_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_ip_match_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_ip_match_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_ip_match_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_ip_match_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_dns_match_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_dns_match_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_dns_match_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_dns_match_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_email_match_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_email_match_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_email_match_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_email_match_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

Once a match has been found, the entries are examined to see if they have
an appropriate LDAP attribute for the filter-type in use. The default
attribute names for this comparison are from the default schema (and are
also shown below), but you can also define your own if you want.

    ldapfilter_ldap_ip_from_attr          spamAssassinFilterClient
    ldapfilter_ldap_rdns_from_attr        spamAssassinFilterClient
    ldapfilter_ldap_helo_from_attr        spamAssassinFilterHelo
    ldapfilter_ldap_env_from_attr         spamAssassinFilterEnvFrom
    ldapfilter_ldap_env_to_attr           spamAssassinFilterEnvTo
    ldapfilter_ldap_msg_from_attr         spamAssassinFilter822From
    ldapfilter_ldap_msg_rplyto_attr       spamAssassinFilter822RplyTo
    ldapfilter_ldap_msg_tocc_attr         spamAssassinFilter822To
    ldapfilter_ldap_msg_uri_attr          spamAssassinFilter822Uri

=cut

	#
	# read and verify ldapfilter_ldap_ip_from_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_ip_from_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_ip_from_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_ip_from_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_rdns_from_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_rdns_from_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_rdns_from_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_rdns_from_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_helo_from_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_helo_from_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_helo_from_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_helo_from_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_env_from_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_env_from_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_env_from_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_env_from_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_env_to_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_env_to_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_env_to_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_env_to_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_msg_from_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_msg_from_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_msg_from_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_msg_from_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_msg_rplyto_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_msg_rplyto_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_msg_rplyto_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_msg_rplyto_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_msg_tocc_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_msg_tocc_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_msg_tocc_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_msg_tocc_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_msg_uri_attr
	#
	if ($config->{key} eq 'ldapfilter_ldap_msg_uri_attr') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_msg_uri_attr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute name; using default value of ".
				"\"$self->{ldap_msg_uri_attr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

The attribute values to match against for scoring purposes, which you
will probably need to define if you also defined your own attributes.

    ldapfilter_ldap_blacklist_val         BLACKLISTED
    ldapfilter_ldap_darklist_val          DARKLISTED
    ldapfilter_ldap_lightlist_val         LIGHTLISTED
    ldapfilter_ldap_whitelist_val         WHITELISTED

=cut

	#
	# read and verify ldapfilter_ldap_blacklist_val
	#
	if ($config->{key} eq 'ldapfilter_ldap_blacklist_val') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_blacklist_val} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute value; using default value of ".
				"\"$self->{ldap_blacklist_val}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_darklist_val
	#
	if ($config->{key} eq 'ldapfilter_ldap_darklist_val') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_darklist_val} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute value; using default value of ".
				"\"$self->{ldap_darklist_val}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_lightlist_val
	#
	if ($config->{key} eq 'ldapfilter_ldap_lightlist_val') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_lightlist_val} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute value; using default value of ".
				"\"$self->{ldap_darklist_val}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_ldap_whitelist_val
	#
	if ($config->{key} eq 'ldapfilter_ldap_whitelist_val') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{ldap_whitelist_val} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"attribute value; using default value of ".
				"\"$self->{ldap_whitelist_val}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=head2 Resource- and Type-Specific Options

The following options determine whether or not the plug-in even bothers to
generate queries for certain resource types. Note that disabling a rule
will not have this result, since *all* of the queries are built and issued
once any rule is called. In order to eliminate a whole class of resource
queries, you have to tell the plug-in which ones it should not bother with.
As far as SpamAssassin is concerned, the related rules just seem to always
return "no match". Note that all of these options default to the "on"
toggle position. 

    ldapfilter_search_ip_from             on    # on|off
    ldapfilter_search_rdns_from           on    # on|off
    ldapfilter_search_helo_from           on    # on|off
    ldapfilter_search_env_from            on    # on|off
    ldapfilter_search_env_to              on    # on|off
    ldapfilter_search_msg_from            on    # on|off
    ldapfilter_search_msg_rplyto          on    # on|off
    ldapfilter_search_msg_tocc            on    # on|off
    ldapfilter_search_msg_uri             on    # on|off

=cut

	#
	# read and verify ldapfilter_search_ip_from
	#
	if ($config->{key} eq 'ldapfilter_search_ip_from') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_ip_from} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_ip_from}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_rdns_from
	#
	if ($config->{key} eq 'ldapfilter_search_rdns_from') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_rdns_from} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_rdns_from}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_helo_from
	#
	if ($config->{key} eq 'ldapfilter_search_helo_from') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_helo_from} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_helo_from}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_env_from
	#
	if ($config->{key} eq 'ldapfilter_search_env_from') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_env_from} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_env_from}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_env_to
	#
	if ($config->{key} eq 'ldapfilter_search_env_to') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_env_to} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_env_to}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_msg_from
	#
	if ($config->{key} eq 'ldapfilter_search_msg_from') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_msg_from} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_msg_from}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_msg_rplyto
	#
	if ($config->{key} eq 'ldapfilter_search_msg_rplyto') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_msg_rplyto} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_msg_rplyto}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_msg_tocc
	#
	if ($config->{key} eq 'ldapfilter_search_msg_tocc') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_msg_tocc} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_msg_tocc}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_msg_uri
	#
	if ($config->{key} eq 'ldapfilter_search_msg_uri') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_msg_uri} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_msg_uri}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

The next two options specify the header fields where we should look for
envelope sender and recipient data, as provided in the SMTP 'MAIL FROM' and
'RCPT TO' envelope exchange. By default, we'll look for the envelope
sender in the 'Return-Path' header field, but you can override that with
another header field in the 'ldapfilter_env_from_header' option.
There is no standardized header for envelope recipient data, so we don't
have a reasonable starting point for that. If you can configure your server
to generate something like an X-Envelope-To, specify the name of that
header field here. Note that envelope recipient checks won't be done until
this option is set, regardless of the 'ldapfilter_search_env_to' option.

    ldapfilter_env_from_header            ""    # not used
    ldapfilter_env_to_header              ""    # not used

=cut

	#
	# read and verify ldapfilter_env_from_header
	#
	if ($config->{key} eq 'ldapfilter_env_from_header') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{env_from_header} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"header field name; using default value of ".
				"\"$self->{env_from_header}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_env_to_header
	#
	if ($config->{key} eq 'ldapfilter_env_to_header') {

		if ($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{env_to_header} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"header field name; using default value of ".
				"\"$self->{env_to_header}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

'ldapfilter_recipient_limit' sets a cap on the number of recipient
addresses that will be searched ("0" is no limit). Note that this count
specifically applies to LDAP searches, and not to addresses that are
filtered out before a search takes place (see ldapfilter_recipient_filter),
nor does it affect name recursion (see ldapfilter_recursion_limit). Keep
in mind that large lists of names that are infinitely recursed will
negatively affect the cumulative amount of time required to process a
message, and long operations can trigger timeouts in SpamAssassin or
related processes. For this reason, the default value for this settings
is "10" instead of "0".

    ldapfilter_recipient_limit            10    # "0" = no limit

=cut

	#
	# read and verify ldapfilter_recipient_limit
	#
	if ($config->{key} eq 'ldapfilter_recipient_limit') {

		if ($config->{value} =~ /^[\'\"]?\s*(\d+?)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{recipient_limit} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"recipient limit; using default value of ".
				"\"$self->{recipient_limit}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

'ldapfilter_recipient_filter' provides a domain name mask for recipient
addresses, in case you only want to check the blacklist database for a
specific domain.

    ldapfilter_recipient_filter           ""    # not used

=cut

	#
	# read and verify ldapfilter_recipient_filter
	#
	# NOTE: try to make this an array or hash
	#
	if ($config->{key} eq 'ldapfilter_recipient_filter') {

		if (($config->{value} =~ /^[\'\"]?\s*(\S+?)\s*[\'\"]?$/i) &&
			(verify_domain_name($1) == 1)) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{recipient_filter} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"domain filter; using default value of ".
				"\"$self->{recipient_filter}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

'ldapfilter_cidr_lookups' determines if parent IPv4 netblocks are
located by CIDR matching ("on"), or if they are located by simply chopping
the right-most octet from the address ("off"). Using CIDR lookups provides
fine-granularity filters, but imposes significant resource requirements on
the search operation, since there are 22 possible CIDR prefixes for each
address (these are the initial /32, and the subsequent lookups for /29
through /8). Disabling CIDR lookups is much faster and lighter, and it
uses the same logic as found in postfix filters (meaning you can share
filter entries), but it is a very rough-grained filtering mechanism. One
other consideration to keep in mind here is the potential for negative
interaction with 'ldapfilter_recursion_limit', which can cause the
CIDR matching to stop short of the full /8 lookups.

    ldapfilter_cidr_lookups               on    # on|off

=cut

	#
	# read and verify ldapfilter_cidr_lookups
	#
	if ($config->{key} eq 'ldapfilter_cidr_lookups') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{cidr_lookups} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{ldap_persistency}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

'ldapfilter_recursion_limit' determines how many levels of a resource
name will be searched for a match ("0" is no limit, meaning that every
element in the name can be searched). One level of recursion is often enough
to match against a parent domain or net-block if the email address or host
IP address didn't match an explicit entry, but this doesn't work when the
resource name is deeply nested. Also remember that recursion stops when all
of the elements in the name have been exhausted, so infinite recursion
never really is infinite.

    ldapfilter_recursion_limit            0     # "0" = no limit

=cut

	#
	# read and verify ldapfilter_recursion_limit
	#
	if ($config->{key} eq 'ldapfilter_recursion_limit') {

		if ($config->{value} =~ /^[\'\"]?\s*(\d+?)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{recursion_limit} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"recursion value; using default value of ".
				"\"$self->{recursion_limit}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

'ldapfilter_verify_resources' determines if malformed resources should be
processed or discarded. If this option is enabled (the default setting),
malformed IP addresses, domain names and email addresses will be ignored
instead of being searched. Although some spammers are known to purposely
generate malformed data in an effort to escape repurcussions for their
prior acts, there are some potential security risks in allowing random
strings of characters to be passed in LDAP queries, so we default to the
safe position.

    ldapfilter_verify_resources           on    # on|off

=cut

	#
	# read and verify ldapfilter_verify_resources
	#
	if ($config->{key} eq 'ldapfilter_verify_resources') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{verify_resources} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{verify_resources}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

=pod

The next set of options define whether or not LDAPfilter should search
for related DNS resources. For example, the 'search_related_ptr'
option specifies that DNS PTR lookups should be issued for any IP
addresses that are encountered, while the 'search_related_mx' option
specifies that DNS MX lookups should be issued for any domain names
that are discovered. Any successful matches against the related
resources will be treated as if the original query had succeeded.
Note that while these kinds of searches are good at catching spammers
who hide behind multiple networks or domains but share common resources
like nameservers, enabling all of these options can double the query
workload so they are off by default.

    ldapfilter_search_related_ptr         off   # on|off
    ldapfilter_search_related_a           off   # on|off
    ldapfilter_search_related_ns          off   # on|off
    ldapfilter_search_related_mx          off   # on|off

=cut

	#
	# read and verify ldapfilter_search_related_ptr
	#
	if ($config->{key} eq 'ldapfilter_search_related_ptr') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_related_ptr} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_related_ptr}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_related_a
	#
	if ($config->{key} eq 'ldapfilter_search_related_a') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_related_a} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_related_a}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_related_ns
	#
	if ($config->{key} eq 'ldapfilter_search_related_ns') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_related_ns} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_related_ns}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# read and verify ldapfilter_search_related_mx
	#
	if ($config->{key} eq 'ldapfilter_search_related_mx') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("LDAPfilter\: $config->{key}\: ".
				"using \"$1\"");

			$self->{search_related_mx} = $1;
		}

		else {
			dbg ("LDAPfilter\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{search_related_mx}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# all other config statements are unknown
	#
	return 0;
}

#
# define the main eval calls
#

=head1 RULES AND SCORES

LDAPfilter "works" by defining SpamAssassin rules that are called
as a message is processed. Each rule that matches returns a score
for that rule.

Note that disabling a rule does not prevent a search from being
executed. LDAPfilter uses a single instance of a message and an LDAP
session, so if any rule is called all of them will get processed. If
you want to actually stop a rule from being executed (as opposed to
not being scored), use the appropriate option(s) described in the
preceeding section.

Note that SpamAssassin requires that rules and score values be
defined in a .cf file that can be found by SpamAssassin on startup.

A default ruleset and scoring file is available at
http://www.ntrg.com/misc/ldapfilter/

Do not place this file into the master SpamAssassin folder tree,
as those folders are deleted whenever SpamAssassin is upgraded.

=cut

=head2 SMTP Client IP Address

Blacklist/whitelist mail from IP networks. Note that there's no way to
corollate remote IP addresses to their real CIDR netblocks, so all
matching has to occur on octet boundaries.

    header LDAP_IP_FROM_BLACK       eval:ldap_ip_from_blacklisted()
    describe LDAP_IP_FROM_BLACK     Checks SMTP client IP for blacklist
    tflags LDAP_IP_FROM_BLACK       net
    score LDAP_IP_FROM_BLACK        50.0

    header LDAP_IP_FROM_DARK        eval:ldap_ip_from_darklisted()
    describe LDAP_IP_FROM_DARK      Checks SMTP client IP for darklist
    tflags LDAP_IP_FROM_DARK        net
    score LDAP_IP_FROM_DARK         5.0

    header LDAP_IP_FROM_LIGHT       eval:ldap_ip_from_lightlisted()
    describe LDAP_IP_FROM_LIGHT     Checks SMTP client IP for lightlist
    tflags LDAP_IP_FROM_LIGHT       net
    score LDAP_IP_FROM_LIGHT        -10.0

    header LDAP_IP_FROM_WHITE       eval:ldap_ip_from_whitelisted()
    describe LDAP_IP_FROM_WHITE     Checks SMTP client IP for whitelist
    tflags LDAP_IP_FROM_WHITE       net
    score LDAP_IP_FROM_WHITE        -100.0

=cut

sub ldap_ip_from_blacklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{ip_from_blacklisted};
}

sub ldap_ip_from_darklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{ip_from_darklisted};
}

sub ldap_ip_from_lightlisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{ip_from_lightlisted};
}

sub ldap_ip_from_whitelisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{ip_from_whitelisted};
}

=head2 SMTP Client Reverse-DNS Domain Name

Blacklist/whitelist mail associated with a domain name, as determined by
reverse DNS lookups. This is useful if you're trying to list an organization
with multiple or frequently-changing network assingments.

    header LDAP_RDNS_FROM_BLACK     eval:ldap_rdns_from_blacklisted()
    describe LDAP_RDNS_FROM_BLACK   Checks SMTP client rDNS for blacklist
    tflags LDAP_RDNS_FROM_BLACK     net
    score LDAP_RDNS_FROM_BLACK      50.0

    header LDAP_RDNS_FROM_DARK      eval:ldap_rdns_from_darklisted()
    describe LDAP_RDNS_FROM_DARK    Checks SMTP client rDNS for darklist
    tflags LDAP_RDNS_FROM_DARK      net
    score LDAP_RDNS_FROM_DARK       5.0

    header LDAP_RDNS_FROM_LIGHT     eval:ldap_rdns_from_lightlisted()
    describe LDAP_RDNS_FROM_LIGHT   Checks SMTP client rDNS for lightlist
    tflags LDAP_RDNS_FROM_LIGHT     net
    score LDAP_RDNS_FROM_LIGHT      -10.0

    header LDAP_RDNS_FROM_WHITE     eval:ldap_rdns_from_whitelisted()
    describe LDAP_RDNS_FROM_WHITE   Checks SMTP client rDNS for whitelist
    tflags LDAP_RDNS_FROM_WHITE     net
    score LDAP_RDNS_FROM_WHITE      -100.0

=cut

sub ldap_rdns_from_blacklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{rdns_from_blacklisted};
}

sub ldap_rdns_from_darklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{rdns_from_darklisted};
}

sub ldap_rdns_from_lightlisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{rdns_from_lightlisted};
}

sub ldap_rdns_from_whitelisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{rdns_from_whitelisted};
}

=head2 SMTP Client HELO Identifier

HELO domains are often forged. One feature of this is that you can add a
blacklist entry for your own mail server netblock or reverse domain name, 
and catch spammers that are trying to pass themselves off as you. You might
also need to whitelist important mail servers that use malformed or illegal
HELO identifiers (such as a small business behind a NAT). Keep in mind that
these can all be forged, so it's best to just lightlist them.

    header LDAP_HELO_FROM_BLACK     eval:ldap_helo_from_blacklisted()
    describe LDAP_HELO_FROM_BLACK   Checks SMTP client HELO for blacklist
    tflags LDAP_HELO_FROM_BLACK     net
    score LDAP_HELO_FROM_BLACK      50.0

    header LDAP_HELO_FROM_DARK      eval:ldap_helo_from_darklisted()
    describe LDAP_HELO_FROM_DARK    Checks SMTP client HELO for darklist
    tflags LDAP_HELO_FROM_DARK      net
    score LDAP_HELO_FROM_DARK       5.0

    header LDAP_HELO_FROM_LIGHT     eval:ldap_helo_from_lightlisted()
    describe LDAP_HELO_FROM_LIGHT   Checks SMTP client HELO for lightlist
    tflags LDAP_HELO_FROM_LIGHT     net
    score LDAP_HELO_FROM_LIGHT      -10.0

    header LDAP_HELO_FROM_WHITE     eval:ldap_helo_from_whitelisted()
    describe LDAP_HELO_FROM_WHITE   Checks SMTP client HELO for whitelist
    tflags LDAP_HELO_FROM_WHITE     net
    score LDAP_HELO_FROM_WHITE      -100.0

=cut

sub ldap_helo_from_blacklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{helo_from_blacklisted};
}

sub ldap_helo_from_darklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{helo_from_darklisted};
}

sub ldap_helo_from_lightlisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{helo_from_lightlisted};
}

sub ldap_helo_from_whitelisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{helo_from_whitelisted};
}

=head2 SMTP Envelope MAIL-FROM Command

Not really trustworthy except for bulk marketers that use a "real" email
address that can be blacklisted. These can also be "validated" with SPF.

    header LDAP_ENV_FROM_BLACK      eval:ldap_env_from_blacklisted()
    describe LDAP_ENV_FROM_BLACK    Checks SMTP MAIL-FROM address for blacklist
    tflags LDAP_ENV_FROM_BLACK      net
    score LDAP_ENV_FROM_BLACK       50.0

    header LDAP_ENV_FROM_DARK       eval:ldap_env_from_darklisted()
    describe LDAP_ENV_FROM_DARK     Checks SMTP MAIL-FROM address for darklist
    tflags LDAP_ENV_FROM_DARK       net
    score LDAP_ENV_FROM_DARK        5.0

    header LDAP_ENV_FROM_LIGHT      eval:ldap_env_from_lightlisted()
    describe LDAP_ENV_FROM_LIGHT    Checks SMTP MAIL-FROM address for lightlist
    tflags LDAP_ENV_FROM_LIGHT      net
    score LDAP_ENV_FROM_LIGHT       -10.0

    header LDAP_ENV_FROM_WHITE      eval:ldap_env_from_whitelisted()
    describe LDAP_ENV_FROM_WHITE    Checks SMTP MAIL-FROM address for whitelist
    tflags LDAP_ENV_FROM_WHITE      net
    score LDAP_ENV_FROM_WHITE       -100.0

=cut

sub ldap_env_from_blacklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{env_from_blacklisted};
}

sub ldap_env_from_darklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{env_from_darklisted};
}

sub ldap_env_from_lightlisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{env_from_lightlisted};
}

sub ldap_env_from_whitelisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{env_from_whitelisted};
}

=head2 SMTP Envelope RCPT-TO Command

Envelope recipients are where the local message recipients are listed, so
this is where you should filter on spamtrap addresses and the like. However,
SpamAssassin does not currently provide this data itself, so if you want to
use this feature, you must create an X-Envelope-To: header field in the
message somehow (presumably with a "create header" function in your mail
server), before the message is read by SpamAssassin.

    header LDAP_ENV_TO_BLACK        eval:ldap_env_to_blacklisted()
    describe LDAP_ENV_TO_BLACK      Checks SMTP RCPT-TO address for blacklist
    tflags LDAP_ENV_TO_BLACK        net
    score LDAP_ENV_TO_BLACK         50.0

    header LDAP_ENV_TO_DARK         eval:ldap_env_to_darklisted()
    describe LDAP_ENV_TO_DARK       Checks SMTP RCPT-TO address for darklist
    tflags LDAP_ENV_TO_DARK         net
    score LDAP_ENV_TO_DARK          5.0

    header LDAP_ENV_TO_LIGHT        eval:ldap_env_to_lightlisted()
    describe LDAP_ENV_TO_LIGHT      Checks SMTP RCPT-TO address for lightlist
    tflags LDAP_ENV_TO_LIGHT        net
    score LDAP_ENV_TO_LIGHT         -10.0

    header LDAP_ENV_TO_WHITE        eval:ldap_env_to_whitelisted()
    describe LDAP_ENV_TO_WHITE      Checks SMTP RCPT-TO address for whitelist
    tflags LDAP_ENV_TO_WHITE        net
    score LDAP_ENV_TO_WHITE         -100.0

=cut

sub ldap_env_to_blacklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{env_to_blacklisted};
}

sub ldap_env_to_darklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{env_to_darklisted};
}

sub ldap_env_to_lightlisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{env_to_lightlisted};
}

sub ldap_env_to_whitelisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{env_to_whitelisted};
}

=head2 RFC-822 Message From: Header Field

Not really trustworthy except for bulk marketers that use a "real" email
address that can be blacklisted.

    header LDAP_MSG_FROM_BLACK      eval:ldap_msg_from_blacklisted()
    describe LDAP_MSG_FROM_BLACK    Checks RFC-822 From: address for blacklist
    tflags LDAP_MSG_FROM_BLACK      net
    score LDAP_MSG_FROM_BLACK       50.0

    header LDAP_MSG_FROM_DARK       eval:ldap_msg_from_darklisted()
    describe LDAP_MSG_FROM_DARK     Checks RFC-822 From: address for darklist
    tflags LDAP_MSG_FROM_DARK       net
    score LDAP_MSG_FROM_DARK        5.0

    header LDAP_MSG_FROM_LIGHT      eval:ldap_msg_from_lightlisted()
    describe LDAP_MSG_FROM_LIGHT    Checks RFC-822 From: address for lightlist
    tflags LDAP_MSG_FROM_LIGHT      net
    score LDAP_MSG_FROM_LIGHT       -10.0

    header LDAP_MSG_FROM_WHITE      eval:ldap_msg_from_whitelisted()
    describe LDAP_MSG_FROM_WHITE    Checks RFC-822 From: address for whitelist
    tflags LDAP_MSG_FROM_WHITE      net
    score LDAP_MSG_FROM_WHITE       -100.0

=cut

sub ldap_msg_from_blacklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_from_blacklisted};
}

sub ldap_msg_from_darklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_from_darklisted};
}

sub ldap_msg_from_lightlisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_from_lightlisted};
}

sub ldap_msg_from_whitelisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_from_whitelisted};
}

=head2 RFC-822 Message Reply-To: Header Field

Some idiots try to hide their "From:" identity but will still provide a
"Reply-To:" header with their real address. I use this to catch Nigerian spam for
Yahoo mail accounts and such, while lightlisting From: headers from people I know.
Note that some mailing groups are also known to use this header.

    header LDAP_MSG_RPLYTO_BLACK    eval:ldap_msg_rplyto_blacklisted()
    describe LDAP_MSG_RPLYTO_BLACK  Checks RFC-822 Reply-To: address for blacklist
    tflags LDAP_MSG_RPLYTO_BLACK    net
    score LDAP_MSG_RPLYTO_BLACK     50.0

    header LDAP_MSG_RPLYTO_DARK     eval:ldap_msg_rplyto_darklisted()
    describe LDAP_MSG_RPLYTO_DARK   Checks RFC-822 Reply-To: address for darklist
    tflags LDAP_MSG_RPLYTO_DARK     net
    score LDAP_MSG_RPLYTO_DARK      5.0

    header LDAP_MSG_RPLYTO_LIGHT    eval:ldap_msg_rplyto_lightlisted()
    describe LDAP_MSG_RPLYTO_LIGHT  Checks RFC-822 Reply-To: address for lightlist
    tflags LDAP_MSG_RPLYTO_LIGHT    net
    score LDAP_MSG_RPLYTO_LIGHT     -10.0

    header LDAP_MSG_RPLYTO_WHITE    eval:ldap_msg_rplyto_whitelisted()
    describe LDAP_MSG_RPLYTO_WHITE  Checks RFC-822 Reply-To: address for whitelist
    tflags LDAP_MSG_RPLYTO_WHITE    net
    score LDAP_MSG_RPLYTO_WHITE     -100.0

=cut

sub ldap_msg_rplyto_blacklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_rplyto_blacklisted};
}

sub ldap_msg_rplyto_darklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_rplyto_darklisted};
}

sub ldap_msg_rplyto_lightlisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_rplyto_lightlisted};
}

sub ldap_msg_rplyto_whitelisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_rplyto_whitelisted};
}

=head2 RFC-822 Message To: and Cc: Header Fields

These are useful if you want to blacklist a spamtrap address, or if you
want to whitelist all traffic going to a mailing list address (the latter is
particularly useful with SpamAssassin's auto-whitelist feature, since any
private replies to you and the mailing list will both be flagged, with the
message sender inheriting the benefit of the whitelist score). If you plan
to make heavy use of this ruleset, make sure that ldapfilter_rcpt_limit
is not set to too low a value, or else you might miss some hits.

    header LDAP_MSG_TO_BLACK        eval:ldap_msg_tocc_blacklisted()
    describe LDAP_MSG_TO_BLACK      Checks RFC-822 To:/Cc: addresses for blacklist
    tflags LDAP_MSG_TO_BLACK        net
    score LDAP_MSG_TO_BLACK         50.0

    header LDAP_MSG_TO_DARK         eval:ldap_msg_tocc_darklisted()
    describe LDAP_MSG_TO_DARK       Checks RFC-822 To:/Cc: addresses for darklist
    tflags LDAP_MSG_TO_DARK         net
    score LDAP_MSG_TO_DARK          5.0

    header LDAP_MSG_TO_LIGHT        eval:ldap_msg_tocc_lightlisted()
    describe LDAP_MSG_TO_LIGHT      Checks RFC-822 To:/Cc: addresses for lightlist
    tflags LDAP_MSG_TO_LIGHT        net
    score LDAP_MSG_TO_LIGHT         -10.0

    header LDAP_MSG_TO_WHITE        eval:ldap_msg_tocc_whitelisted()
    describe LDAP_MSG_TO_WHITE      Checks RFC-822 To:/Cc: addresses for whitelist
    tflags LDAP_MSG_TO_WHITE        net
    score LDAP_MSG_TO_WHITE         -100.0

=cut

sub ldap_msg_tocc_blacklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_tocc_blacklisted};
}

sub ldap_msg_tocc_darklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_tocc_darklisted};
}

sub ldap_msg_tocc_lightlisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_tocc_lightlisted};
}

sub ldap_msg_tocc_whitelisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_tocc_whitelisted};
}

=head2 RFC-822 Message Body URI

These are useful if you want to blacklist a particular URI. Currently these tests
only look at http: and mailto: URIs. For mailto links, the test first tries the
complete URI, then the email address, and then recurses through the mail domain
hierarchy. For http links, the test first tries the complete URI then recursively
removes each path element, then any embedded authentication information, then the
port number element, and finally recurses through the domain hierarchy.

    header LDAP_MSG_URI_BLACK       eval:ldap_msg_uri_blacklisted()
    describe LDAP_MSG_URI_BLACK     Checks RFC-822 message URIs for blacklist
    tflags LDAP_MSG_URI_BLACK       net
    score LDAP_MSG_URI_BLACK        50.0

    header LDAP_MSG_URI_DARK        eval:ldap_msg_uri_darklisted()
    describe LDAP_MSG_URI_DARK      Checks RFC-822 message URIs for darklist
    tflags LDAP_MSG_URI_DARK        net
    score LDAP_MSG_URI_DARK         5.0

    header LDAP_MSG_URI_LIGHT       eval:ldap_msg_uri_lightlisted()
    describe LDAP_MSG_URI_LIGHT     Checks RFC-822 message URIs for lightlist
    tflags LDAP_MSG_URI_LIGHT       net
    score LDAP_MSG_URI_LIGHT        -10.0

    header LDAP_MSG_URI_WHITE       eval:ldap_msg_uri_whitelisted()
    describe LDAP_MSG_URI_WHITE     Checks RFC-822 message URIs for whitelist
    tflags LDAP_MSG_URI_WHITE       net
    score LDAP_MSG_URI_WHITE        -100.0

=cut

sub ldap_msg_uri_blacklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_uri_blacklisted};
}

sub ldap_msg_uri_darklisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_uri_darklisted};
}

sub ldap_msg_uri_lightlisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_uri_lightlisted};
}

sub ldap_msg_uri_whitelisted {

	my ($self, $permsgstatus) = @_;
	$self->scan_for_resources($permsgstatus) unless $permsgstatus->{searched};
	return $permsgstatus->{msg_uri_whitelisted};
}

=head1 REQUIREMENT

Requires SpamAssassin 3.0.x and Net::LDAP

Optional features separately require Net::LDAPS and Net::LDAPI, Net::DNS, and
Sys::Hostname::Long

=cut

#
# see what data we can find in the input, and execute the appropriate searches
#
# this is the main loop
#
sub scan_for_resources {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# set the default return code values
	#
	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	$permsgstatus->{ip_from_blacklisted} = 0;
	$permsgstatus->{ip_from_darklisted} = 0;
	$permsgstatus->{ip_from_lightlisted} = 0;
	$permsgstatus->{ip_from_whitelisted} = 0;

	$permsgstatus->{rdns_from_blacklisted} = 0;
	$permsgstatus->{rdns_from_darklisted} = 0;
	$permsgstatus->{rdns_from_lightlisted} = 0;
	$permsgstatus->{rdns_from_whitelisted} = 0;

	$permsgstatus->{helo_from_blacklisted} = 0;
	$permsgstatus->{helo_from_darklisted} = 0;
	$permsgstatus->{helo_from_lightlisted} = 0;
	$permsgstatus->{helo_from_whitelisted} = 0;

	$permsgstatus->{env_from_blacklisted} = 0;
	$permsgstatus->{env_from_darklisted} = 0;
	$permsgstatus->{env_from_lightlisted} = 0;
	$permsgstatus->{env_from_whitelisted} = 0;

	$permsgstatus->{env_to_blacklisted} = 0;
	$permsgstatus->{env_to_darklisted} = 0;
	$permsgstatus->{env_to_lightlisted} = 0;
	$permsgstatus->{env_to_whitelisted} = 0;

	$permsgstatus->{msg_from_blacklisted} = 0;
	$permsgstatus->{msg_from_darklisted} = 0;
	$permsgstatus->{msg_from_lightlisted} = 0;
	$permsgstatus->{msg_from_whitelisted} = 0;

	$permsgstatus->{msg_tocc_blacklisted} = 0;
	$permsgstatus->{msg_tocc_darklisted} = 0;
	$permsgstatus->{msg_tocc_lightlisted} = 0;
	$permsgstatus->{msg_tocc_whitelisted} = 0;

	#
	# set the {searched} flag to prevent multiple lookups per message
	#
	$permsgstatus->{searched} = 1;

	#
	# see if there's any data that can be parsed
	#
	if (($permsgstatus->get('X-Spam-Relays-Untrusted') =~ /^$/) &&
		($permsgstatus->get('EnvelopeFrom') =~ /^$/) &&
		($permsgstatus->get('From') =~ /^$/) &&
		($permsgstatus->get('Reply-To') =~ /^$/) &&
		($permsgstatus->get('ToCc') =~ /^$/)) {

		dbg ("LDAPfilter\: no input data to search for " .
			"... terminating");

		return 0;
	}

	#
	# input data found
	#
	dbg ("LDAPfilter\: input data found ... proceeding with searches");

	#
	# see if an LDAP session is already active
	#
	if (! defined $self->{ldap_session}) {

		#
		# try to create a session
		#
		if ($self->create_ldap_session($permsgstatus) == 0) {

			#
			# unable to create a session so exit
			#
			return 0;
		}
	}

	#
	# an LDAP session appears active, but probe it to be sure
	#
	else {
		dbg ("LDAPfilter\: LDAP session appears to be active " .
			"... attempting to reuse");

		if ($self->test_ldap_session($permsgstatus) == 0) {

			#
			# the probe failed, so destroy the old session
			#
			dbg ("LDAPfilter\: LDAP session appears to have died " .
				"... killing it off");

			$self->destroy_ldap_session($permsgstatus);

			#
			# try to establish a new session
			#
			if ($self->create_ldap_session($permsgstatus) == 0) {

				#
				# unable to create a session so exit
				#
				return 0;
			}
		}
	}

	#
	# call the lookup sub-functions and return any hard errors
	#
	if ($self->look_for_ip_from($permsgstatus) == 0) {

		return 0;
	}

	if ($self->look_for_rdns_from($permsgstatus) == 0) {

		return 0;
	}

	if ($self->look_for_helo_from($permsgstatus) == 0) {

		return 0;
	}

	if ($self->look_for_env_from($permsgstatus) == 0) {

		return 0;
	}

	if ($self->look_for_env_to($permsgstatus) == 0) {

		return 0;
	}

	if ($self->look_for_msg_from($permsgstatus) == 0) {

		return 0;
	}

	if ($self->look_for_msg_rplyto($permsgstatus) == 0) {

		return 0;
	}

	if ($self->look_for_msg_tocc($permsgstatus) == 0) {

		return 0;
	}

	if ($self->look_for_msg_uri($permsgstatus) == 0) {

		return 0;
	}

	#
	# no more resources to search against
	#
	dbg ("LDAPfilter\: no more input data to search " .
		"... terminating");

	#
	# close the session unless persistency is enabled
	#
	if ($self->{ldap_persistency} =~ /off/i) {

		$self->destroy_ldap_session($permsgstatus);
	}
}

sub look_for_ip_from {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# purge any leftover data that might be around
	#
	undef $permsgstatus->{raw_resource_name};
	undef $permsgstatus->{ldap_resource_name};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	#
	# see if we should be here
	#
	if ($self->{search_ip_from} =~ /off/i) {

		dbg ("LDAPfilter\: SMTP client IP address searches " .
			"disabled ... skipping");

		return 1;
	}

	#
	# look for the sender's IP address
	#
	if ($permsgstatus->get('X-Spam-Relays-Untrusted') =~ /ip=([\d\.]+)\s/) {

		$permsgstatus->{raw_resource_name} = $1;
	}

	#
	# data is missing, so bail out
	#
	else {
		dbg ("LDAPfilter\: SMTP client IP address field " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# clean the input data
	#
	chomp ($permsgstatus->{raw_resource_name});

	$permsgstatus->{raw_resource_name} =~ s/^\s+//;
	$permsgstatus->{raw_resource_name} =~ s/\s+$//;

	#
	# if it's null, skip it
	#
	if ($permsgstatus->{raw_resource_name} eq "") {

		dbg ("LDAPfilter\: SMTP client IP address data " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# see if it's a valid address
	#
	if (($self->{verify_resources} =~ /^on$/i) &&
		(verify_ip_address($permsgstatus->{raw_resource_name}) == 0)) {

		dbg ("LDAPfilter\: \"" . $permsgstatus->{raw_resource_name} . "\"" .
			" is not a valid client IP address ... skipping");

		return 1;
	}

	#
	# copy the seed resource name for ldap lookups
	#
	$permsgstatus->{ldap_resource_name} = $permsgstatus->{raw_resource_name};

	#
	# see if we are using CIDR lookups and if this is a raw addr
	#
	if (($self->{cidr_lookups} =~ /on/i) &&
		($permsgstatus->{ldap_resource_name} =~
		/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/)) {

		$permsgstatus->{ldap_resource_name} =
			$permsgstatus->{ldap_resource_name} . "/32";
	}

	dbg ("LDAPfilter\: SMTP client IP address determined as " .
		"\"" . $permsgstatus->{ldap_resource_name} . "\"");

	$permsgstatus->{ldap_resource_attr} = $self->{ldap_ip_from_attr};

	#
	# execute the search and return any hard failures
	#
	if ($self->generate_ldap_search($permsgstatus) == 0) {

		return 0;
	}

	#
	# return if the search didn't produce results
	#
	if (! defined $permsgstatus->{ldap_search_result_value}) {

		return 1;
	}

	#
	# we got results
	#
	else {
		if ($permsgstatus->{ldap_search_result_blacklisted} == 1) {
			$permsgstatus->{ip_from_blacklisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_darklisted} == 1) {
			$permsgstatus->{ip_from_darklisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_lightlisted} == 1) {
			$permsgstatus->{ip_from_lightlisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_whitelisted} == 1) {
			$permsgstatus->{ip_from_whitelisted} = 1;
		}
	}

	#
	# go back to the main loop
	#
	return 1;
}

sub look_for_rdns_from {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# purge any leftover data that might be around
	#
	undef $permsgstatus->{raw_resource_name};
	undef $permsgstatus->{ldap_resource_name};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	#
	# see if we should be here
	#
	if ($self->{search_rdns_from} =~ /off/i) {

		dbg ("LDAPfilter\: SMTP client domain name searches " .
			"disabled ... skipping");

		return 1;
	}

	#
	# look for the sender's reverse DNS domain name
	#
	if ($permsgstatus->get('X-Spam-Relays-Untrusted') =~ /rdns=(\S*)\s/) {

		$permsgstatus->{raw_resource_name} = $1;
	}

	#
	# data is missing, so bail out
	#
	else {
		dbg ("LDAPfilter\: SMTP client domain name field " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# clean the input data
	#
	chomp ($permsgstatus->{raw_resource_name});

	$permsgstatus->{raw_resource_name} =~ s/^\s+//;
	$permsgstatus->{raw_resource_name} =~ s/\s+$//;

	#
	# if it's null, skip it
	#
	if ($permsgstatus->{raw_resource_name} eq "") {

		dbg ("LDAPfilter\: SMTP client domain name data " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# copy the seed resource name for ldap lookups
	#
	$permsgstatus->{ldap_resource_name} = $permsgstatus->{raw_resource_name};

	#
	# see if it's an address literal (SA uses "!" as literal markers)
	#
	if ($permsgstatus->{ldap_resource_name} =~
		/\!(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\!/) {

		#
		# rewrite with square brackets
		#
		if (($self->{verify_resources} =~ /^on$/i) &&
			(verify_ip_address($1) == 0)) {

			dbg ("LDAPfilter\: \"" . $permsgstatus->{ldap_resource_name} . "\"" .
				" is not a valid client domain name ... skipping");

			return 1;
		}

		else {
			$permsgstatus->{ldap_resource_name} = "[".$1."]";
		}
	}

	#
	# see if it's a raw IP address
	#
	elsif ($permsgstatus->{ldap_resource_name} =~
		/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) {

		if (($self->{verify_resources} =~ /^on$/i) &&
			(verify_ip_address($permsgstatus->{ldap_resource_name}) == 0)) {

			dbg ("LDAPfilter\: \"" . $permsgstatus->{ldap_resource_name} . "\"" .
				" is not a valid client domain name ... skipping");

			return 1;
		}
	}

	#
	# must be a domain name
	#
	else {
		if (($self->{verify_resources} =~ /^on$/i) &&
			(verify_domain_name($permsgstatus->{ldap_resource_name}) == 0)) {

			dbg ("LDAPfilter\: \"" . $permsgstatus->{ldap_resource_name} . "\"" .
				" is not a valid client domain name ... skipping");

			return 1;
		}
	}

	#
	# see if we are using CIDR lookups and if this is a raw addr
	#
	if (($self->{cidr_lookups} =~ /on/i) &&
		($permsgstatus->{ldap_resource_name} =~
		/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/)) {

		$permsgstatus->{ldap_resource_name} =
			$permsgstatus->{ldap_resource_name} . "/32";
	}

	#
	# all done with tests and cleanup
	#
	dbg ("LDAPfilter\: SMTP client domain name determined as " .
		"\"" . $permsgstatus->{ldap_resource_name} . "\"");

	$permsgstatus->{ldap_resource_attr} = $self->{ldap_rdns_from_attr};

	#
	# execute the search and return any hard failures
	#
	if ($self->generate_ldap_search($permsgstatus) == 0) {

		return 0;
	}

	#
	# return if the search didn't produce results
	#
	if (! defined $permsgstatus->{ldap_search_result_value}) {

		return 1;
	}

	#
	# we got results
	#
	else {
		if ($permsgstatus->{ldap_search_result_blacklisted} == 1) {
			$permsgstatus->{rdns_from_blacklisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_darklisted} == 1) {
			$permsgstatus->{rdns_from_darklisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_lightlisted} == 1) {
			$permsgstatus->{rdns_from_lightlisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_whitelisted} == 1) {
			$permsgstatus->{rdns_from_whitelisted} = 1;
		}
	}

	#
	# go back to the main loop
	#
	return 1;
}

sub look_for_helo_from {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# purge any leftover data that might be around
	#
	undef $permsgstatus->{raw_resource_name};
	undef $permsgstatus->{ldap_resource_name};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	#
	# see if we should be here
	#
	if ($self->{search_helo_from} =~ /off/i) {

		dbg ("LDAPfilter\: SMTP client HELO identifier searches " .
			"disabled ... skipping");

		return 1;
	}

	#
	# look for the HELO identifier
	#
	if ($permsgstatus->get('X-Spam-Relays-Untrusted') =~ /helo=(\S+)\s/) {

		$permsgstatus->{raw_resource_name} = $1;
	}

	#
	# data is missing, so bail out
	#
	else {
		dbg ("LDAPfilter\: SMTP client HELO identifier field " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# clean the input data
	#
	chomp ($permsgstatus->{raw_resource_name});

	$permsgstatus->{raw_resource_name} =~ s/^\s+//;
	$permsgstatus->{raw_resource_name} =~ s/\s+$//;

	#
	# if it's null, skip it
	#
	if ($permsgstatus->{raw_resource_name} eq "") {

		dbg ("LDAPfilter\: SMTP client HELO identifier data " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# copy the seed resource name for ldap lookups
	#
	$permsgstatus->{ldap_resource_name} = $permsgstatus->{raw_resource_name};

	#
	# see if it's an address literal (SA uses "!" as literal markers)
	#
	if ($permsgstatus->{ldap_resource_name} =~
		/\!(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\!/) {

		#
		# rewrite with square brackets
		#
		if (($self->{verify_resources} =~ /^on$/i) &&
			(verify_ip_address($1) == 0)) {

			dbg ("LDAPfilter\: \"" . $permsgstatus->{ldap_resource_name} . "\"" .
				" is not a valid SMTP HELO identifier ... skipping");

			return 1;
		}

		else {
			$permsgstatus->{ldap_resource_name} = "[".$1."]";
		}
	}

	#
	# see if it's a raw IP address
	#
	elsif ($permsgstatus->{ldap_resource_name} =~
		/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) {

		if (($self->{verify_resources} =~ /^on$/i) &&
			(verify_ip_address($permsgstatus->{ldap_resource_name}) == 0)) {

			dbg ("LDAPfilter\: \"" . $permsgstatus->{ldap_resource_name} . "\"" .
				" is not a valid SMTP HELO identifier ... skipping");

			return 1;
		}
	}

	#
	# must be a domain name
	#
	else {
		if (($self->{verify_resources} =~ /^on$/i) &&
			(verify_domain_name($permsgstatus->{ldap_resource_name}) == 0)) {

			dbg ("LDAPfilter\: \"" . $permsgstatus->{ldap_resource_name} . "\"" .
				" is not a valid SMTP HELO identifier ... skipping");

			return 1;
		}
	}

	#
	# see if we are using CIDR lookups and if this is a raw addr
	#
	if (($self->{cidr_lookups} =~ /on/i) &&
		($permsgstatus->{ldap_resource_name} =~
		/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/)) {

		$permsgstatus->{ldap_resource_name} =
			$permsgstatus->{ldap_resource_name} . "/32";
	}

	#
	# all done with tests and cleanup
	#
	dbg ("LDAPfilter\: SMTP client HELO identifier determined as " .
		"\"" . $permsgstatus->{ldap_resource_name} . "\"");

	$permsgstatus->{ldap_resource_attr} = $self->{ldap_helo_from_attr};

	#
	# execute the search and return any hard failures
	#
	if ($self->generate_ldap_search($permsgstatus) == 0) {

		return 0;
	}

	#
	# return if the search didn't produce results
	#
	if (! defined $permsgstatus->{ldap_search_result_value}) {

		return 1;
	}

	#
	# we got results
	#
	else {
		if ($permsgstatus->{ldap_search_result_blacklisted} == 1) {
			$permsgstatus->{helo_from_blacklisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_darklisted} == 1) {
			$permsgstatus->{helo_from_darklisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_lightlisted} == 1) {
			$permsgstatus->{helo_from_lightlisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_whitelisted} == 1) {
			$permsgstatus->{helo_from_whitelisted} = 1;
		}
	}

	#
	# go back to the main loop
	#
	return 1;
}

sub look_for_env_from {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# purge any leftover data that might be around
	#
	undef $permsgstatus->{raw_resource_name};
	undef $permsgstatus->{ldap_resource_name};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	#
	# see if we should be here
	#
	if ($self->{search_env_from} =~ /off/i) {

		dbg ("LDAPfilter\: SMTP envelope MAIL-FROM searches " .
			"disabled ... skipping");

		return 1;
	}

	if ($self->{env_from_header} eq "") {

		dbg ("LDAPfilter\: SMTP envelope MAIL-FROM proxy header " .
			"was not specified ... skipping");

		return 1;
	}

	#
	# look for the envelope MAIL-FROM address
	#
	if ($permsgstatus->get($self->{env_from_header}) =~ /^(.+)$/) {

		$permsgstatus->{raw_resource_name} = $1;
	}

	#
	# data is missing, so bail out
	#
	else {
		dbg ("LDAPfilter\: SMTP envelope MAIL-FROM proxy header field " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# clean the input data
	#
	chomp ($permsgstatus->{raw_resource_name});

	$permsgstatus->{raw_resource_name} =~ s/^\s+//;
	$permsgstatus->{raw_resource_name} =~ s/\s+$//;

	#
	# if it's null, skip it
	#
	if ($permsgstatus->{raw_resource_name} eq "") {

		dbg ("LDAPfilter\: SMTP envelope MAIL-FROM proxy header data " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# run it through the normalizer
	#
	$permsgstatus->{raw_resource_name} =
		normalize_email_address($permsgstatus->{raw_resource_name});

	#
	# see if it's a valid address
	#
	if (($self->{verify_resources} =~ /^on$/i) &&
		(verify_email_address($permsgstatus->{raw_resource_name}) == 0)) {

		dbg ("LDAPfilter\: \"" . $permsgstatus->{raw_resource_name} . "\"" .
			" is not a valid SMTP envelope MAIL-FROM address ... skipping");

		return 1;
	}

	#
	# copy the seed resource name for ldap lookups
	#
	$permsgstatus->{ldap_resource_name} = $permsgstatus->{raw_resource_name};

	#
	# prepare the search data
	#
	dbg ("LDAPfilter\: SMTP envelope MAIL-FROM address determined as " .
		"\"" . $permsgstatus->{ldap_resource_name} . "\"");

	$permsgstatus->{ldap_resource_attr} = $self->{ldap_env_from_attr};

	#
	# execute the search and return any hard failures
	#
	if ($self->generate_ldap_search($permsgstatus) == 0) {

		return 0;
	}

	#
	# return if the search didn't produce results
	#
	if (! defined $permsgstatus->{ldap_search_result_value}) {

		return 1;
	}

	#
	# we got results
	#
	else {
		if ($permsgstatus->{ldap_search_result_blacklisted} == 1) {
			$permsgstatus->{env_from_blacklisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_darklisted} == 1) {
			$permsgstatus->{env_from_darklisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_lightlisted} == 1) {
			$permsgstatus->{env_from_lightlisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_whitelisted} == 1) {
			$permsgstatus->{env_from_whitelisted} = 1;
		}
	}

	#
	# go back to the main loop
	#
	return 1;
}

sub look_for_env_to {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# purge any leftover data that might be around
	#
	undef $permsgstatus->{raw_resource_name};
	undef $permsgstatus->{ldap_resource_name};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	#
	# see if we should be here
	#
	if ($self->{search_env_to} =~ /off/i) {

		dbg ("LDAPfilter\: SMTP envelope RCPT-TO searches " .
			"disabled ... skipping");

		return 1;
	}

	if ($self->{env_to_header} eq "") {

		dbg ("LDAPfilter\: SMTP envelope RCPT-TO proxy header " .
			"was not specified ... skipping");

		return 1;
	}

	#
	# look for the envelope RCPT-TO addresses
	#
	if ($permsgstatus->get($self->{env_to_header}) =~ /^(.+)$/) {

		$permsgstatus->{raw_resource_name} = $1;
	}

	#
	# data is missing, so bail out
	#
	else {
		dbg ("LDAPfilter\: SMTP envelope RCPT-TO proxy header field " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# create and populate an array of recipient addresses
	#
	@{$permsgstatus->{env_recipients}} = split(/\,/,
		$permsgstatus->get($self->{env_to_header}));

	#
	# start a counter for the recipient limit
	#
	$permsgstatus->{env_recipient_count} = 0;

	#
	# process each recipient address individually
	#
	foreach my $env_recipient (@{$permsgstatus->{env_recipients}}) {

		#
		# see if we're already at the recipient limit
		#
		if ($self->{recipient_limit} != 0) {

			if ($self->{recipient_limit} ==
				$permsgstatus->{env_recipient_count}) {

				dbg ("LDAPfilter\: maximum number of message " .
					"recipients searched ... skipping");

				last;
			}
		}

		#
		# purge any leftover data that might be around
		#
		undef $permsgstatus->{raw_resource_name};
		undef $permsgstatus->{ldap_resource_name};
		undef $permsgstatus->{ldap_search_result};
		undef $permsgstatus->{ldap_search_result_entry};
		undef $permsgstatus->{ldap_search_result_value};
		undef $permsgstatus->{ldap_search_result_match};

		#
		# set the resource name to the current recipient
		#
		$permsgstatus->{raw_resource_name} = $env_recipient;

		#
		# clean the input data
		#
		chomp ($permsgstatus->{raw_resource_name});

		$permsgstatus->{raw_resource_name} =~ s/^\s+//;
		$permsgstatus->{raw_resource_name} =~ s/\s+$//;

		#
		# if it's null, skip it
		#
		if ($permsgstatus->{raw_resource_name} eq "") {

			next;
		}

		#
		# run it through the normalizer
		#
		$permsgstatus->{raw_resource_name} =
			normalize_email_address($permsgstatus->{raw_resource_name});

		#
		# see if it's a valid address
		#
		if (($self->{verify_resources} =~ /^on$/i) &&
			(verify_email_address($permsgstatus->{raw_resource_name}) == 0)) {

			dbg ("LDAPfilter\: \"" . $permsgstatus->{raw_resource_name} . "\"" .
				" is not a valid SMTP envelope RCPT-TO address ... skipping");

			next;
		}

		#
		# see if the recipient domain filter is set
		#
		if ($self->{recipient_filter} ne "") {

			#
			# test for simple mis-matches
			#
			if ($self->{recipient_filter} ne
				substr($permsgstatus->{raw_resource_name},
				-(length($self->{recipient_filter})))) {

				#
				# recipient isn't in the filter domain, skip it
				#
				dbg ("LDAPfilter\: SMTP envelope RCPT-TO address " .
					"\"" . $permsgstatus->{raw_resource_name} . "\"" .
					" not in filter ... skipping");

				next;
			}

			#
			# test for label boundaries ("ibm.com" =! "fibm.com")
			#
			if (! substr($permsgstatus->{raw_resource_name},
				-(length($self->{recipient_filter})),
				-1) =~ /[\@|\.]/) {

				#
				# recipient isn't in the filter domain, skip it
				#
				dbg ("LDAPfilter\: SMTP envelope RCPT-TO address " .
					"\"" . $permsgstatus->{raw_resource_name} . "\"" .
					" not in filter ... skipping");

				next;
			}
		}

		#
		# increment the recipient count
		#
		$permsgstatus->{env_recipient_count}++;

		#
		# copy the seed resource name for ldap lookups
		#
		$permsgstatus->{ldap_resource_name} = $permsgstatus->{raw_resource_name};

		#
		# prepare the search data
		#
		dbg ("LDAPfilter\: SMTP envelope RCPT-TO address determined as " .
			"\"" . $permsgstatus->{ldap_resource_name} . "\"");

		$permsgstatus->{ldap_resource_attr} = $self->{ldap_env_to_attr};

		#
		# execute the search and return any hard failures
		#
		if ($self->generate_ldap_search($permsgstatus) == 0) {

			return 0;
		}

		#
		# skip this recipient if the search didn't produce results
		#
		if (! defined $permsgstatus->{ldap_search_result_value}) {

			next;
		}

		#
		# we got results
		#
		else {
			if ($permsgstatus->{ldap_search_result_blacklisted} == 1) {
				$permsgstatus->{env_to_blacklisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_darklisted} == 1) {
				$permsgstatus->{env_to_darklisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_lightlisted} == 1) {
				$permsgstatus->{env_to_lightlisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_whitelisted} == 1) {
				$permsgstatus->{env_to_whitelisted} = 1;
			}

			#
			# move to the next recipient address
			#
			next;
		}
	}

	#
	# go back to the main loop
	#
	return 1;
}

sub look_for_msg_from {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# purge any leftover data that might be around
	#
	undef $permsgstatus->{raw_resource_name};
	undef $permsgstatus->{ldap_resource_name};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	#
	# see if we should be here
	#
	if ($self->{search_msg_from} =~ /off/i) {

		dbg ("LDAPfilter\: RFC822 message From\: header field searches " .
			"disabled ... skipping");

		return 1;
	}

	#
	# look for the message From: addresses
	#
	if ($permsgstatus->get('From') =~ /^(.+)$/) {

		$permsgstatus->{raw_resource_name} = $1;
	}

	#
	# data is missing, so bail out
	#
	else {
		dbg ("LDAPfilter\: RFC822 message From\: header field " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# clean the input data
	#
	chomp ($permsgstatus->{raw_resource_name});

	$permsgstatus->{raw_resource_name} =~ s/^\s+//;
	$permsgstatus->{raw_resource_name} =~ s/\s+$//;

	#
	# if it's null, skip it
	#
	if ($permsgstatus->{raw_resource_name} eq "") {

		dbg ("LDAPfilter\: RFC822 message From\: header field data " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# run it through the normalizer
	#
	$permsgstatus->{raw_resource_name} =
		normalize_email_address($permsgstatus->{raw_resource_name});

	#
	# see if it's a valid address
	#
	if (($self->{verify_resources} =~ /^on$/i) &&
		(verify_email_address($permsgstatus->{raw_resource_name}) == 0)) {

		dbg ("LDAPfilter\: \"" . $permsgstatus->{raw_resource_name} . "\"" .
			" is not a valid message From\: address ... skipping");

		return 1;
	}

	#
	# copy the seed resource name for ldap lookups
	#
	$permsgstatus->{ldap_resource_name} = $permsgstatus->{raw_resource_name};

	#
	# prepare the search data
	#
	dbg ("LDAPfilter\: RFC822 message From\: address determined as " .
		"\"" . $permsgstatus->{ldap_resource_name} . "\"");

	$permsgstatus->{ldap_resource_attr} = $self->{ldap_msg_from_attr};

	#
	# execute the search and exit if we get a hard return
	#
	if ($self->generate_ldap_search($permsgstatus) == 0) {

		return 0;
	}

	#
	# return if the search didn't produce results
	#
	if (! defined $permsgstatus->{ldap_search_result_value}) {

		return 1;
	}

	#
	# we got results
	#
	else {
		if ($permsgstatus->{ldap_search_result_blacklisted} == 1) {
			$permsgstatus->{msg_from_blacklisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_darklisted} == 1) {
			$permsgstatus->{msg_from_darklisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_lightlisted} == 1) {
			$permsgstatus->{msg_from_lightlisted} = 1;
		}

		if ($permsgstatus->{ldap_search_result_whitelisted} == 1) {
			$permsgstatus->{msg_from_whitelisted} = 1;
		}
	}

	#
	# go back to the main loop
	#
	return 1;
}

sub look_for_msg_rplyto {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# purge any leftover data that might be around
	#
	undef $permsgstatus->{raw_resource_name};
	undef $permsgstatus->{ldap_resource_name};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	#
	# see if we should be here
	#
	if ($self->{search_msg_rplyto} =~ /off/i) {

		dbg ("LDAPfilter\: RFC822 message Reply-To\: header field searches " .
			"disabled ... skipping");

		return 1;
	}

	#
	# look for the message Reply-To: addresses
	#
	if ($permsgstatus->get('Reply-To') =~ /^(.+)$/) {

		$permsgstatus->{raw_resource_name} = $1;
	}

	#
	# data is missing, so bail out
	#
	else {
		dbg ("LDAPfilter\: RFC822 message Reply-To\: header field " .
			"was not provided ... skipping");

		return 1;
	}

	#
	# create and populate an array of reply-to addresses
	#
	@{$permsgstatus->{msg_replyto}} = split(/\,/, $permsgstatus->get('Reply-To'));

	#
	# start a counter for the recipient limit
	#
	$permsgstatus->{msg_replyto_count} = 0;

	#
	# process each recipient address individually
	#
	foreach my $msg_replyto (@{$permsgstatus->{msg_replyto}}) {

		#
		# see if we're already at the limit
		#
		if ($self->{recipient_limit} != 0) {

			if ($self->{recipient_limit} ==
				$permsgstatus->{msg_replyto_count}) {

				dbg ("LDAPfilter\: maximum number of message " .
					"Reply-To addresses searched ... skipping");

				last;
			}
		}

		#
		# purge any leftover data that might be around
		#
		undef $permsgstatus->{raw_resource_name};
		undef $permsgstatus->{ldap_resource_name};
		undef $permsgstatus->{ldap_search_result};
		undef $permsgstatus->{ldap_search_result_entry};
		undef $permsgstatus->{ldap_search_result_value};
		undef $permsgstatus->{ldap_search_result_match};

		#
		# set the resource name to the current Reply-To address
		#
		$permsgstatus->{raw_resource_name} = $msg_replyto;

		#
		# clean the input data
		#
		chomp ($permsgstatus->{raw_resource_name});

		$permsgstatus->{raw_resource_name} =~ s/^\s+//;
		$permsgstatus->{raw_resource_name} =~ s/\s+$//;

		#
		# if it's null, skip it
		#
		if ($permsgstatus->{raw_resource_name} eq "") {

			next;
		}

		#
		# run it through the normalizer
		#
		$permsgstatus->{raw_resource_name} =
			normalize_email_address($permsgstatus->{raw_resource_name});

		#
		# see if it's a valid address
		#
		if (($self->{verify_resources} =~ /^on$/i) &&
			(verify_email_address($permsgstatus->{raw_resource_name}) == 0)) {

			dbg ("LDAPfilter\: \"" . $permsgstatus->{raw_resource_name} . "\"" .
				" is not a valid message Reply-To address ... skipping");

			next;
		}

		#
		# increment the recipient count
		#
		$permsgstatus->{msg_replyto_count}++;

		#
		# copy the seed resource name for ldap lookups
		#
		$permsgstatus->{ldap_resource_name} = $permsgstatus->{raw_resource_name};

		#
		# prepare the search data
		#
		dbg ("LDAPfilter\: RFC822 message Reply-To address determined as " .
			"\"" . $permsgstatus->{ldap_resource_name} . "\"");

		$permsgstatus->{ldap_resource_attr} = $self->{ldap_msg_rplyto_attr};

		#
		# execute the search and exit if we get a hard return
		#
		if ($self->generate_ldap_search($permsgstatus) == 0) {

			return 0;
		}

		#
		# skip this address if the search didn't produce results
		#
		if (! defined $permsgstatus->{ldap_search_result_value}) {

			next;
		}

		#
		# we got results
		#
		else {
			if ($permsgstatus->{ldap_search_result_blacklisted} == 1) {
				$permsgstatus->{msg_rplyto_blacklisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_darklisted} == 1) {
				$permsgstatus->{msg_rplyto_darklisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_lightlisted} == 1) {
				$permsgstatus->{msg_rplyto_lightlisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_whitelisted} == 1) {
				$permsgstatus->{msg_rplyto_whitelisted} = 1;
			}

			#
			# move to the next Reply-To address
			#
			next;
		}
	}

	#
	# go back to the main loop
	#
	return 1;
}

sub look_for_msg_tocc {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# purge any leftover data that might be around
	#
	undef $permsgstatus->{raw_resource_name};
	undef $permsgstatus->{ldap_resource_name};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	#
	# see if we should be here
	#
	if ($self->{search_msg_tocc} =~ /off/i) {

		dbg ("LDAPfilter\: RFC822 message To\: and Cc\: header field searches " .
			"disabled ... skipping");

		return 1;
	}

	#
	# look for the message To: and Cc: addresses
	#
	if ($permsgstatus->get('ToCc') =~ /^(.+)$/) {

		$permsgstatus->{raw_resource_name} = $1;
	}

	#
	# data is missing, so bail out
	#
	else {
		dbg ("LDAPfilter\: RFC822 message To\: and Cc\: header fields " .
			"were not provided ... skipping");

		return 1;
	}

	#
	# create and populate an array of recipient addresses
	#
	@{$permsgstatus->{msg_recipients}} = split(/\,/, $permsgstatus->get('ToCc'));

	#
	# start a counter for the recipient limit
	#
	$permsgstatus->{msg_recipient_count} = 0;

	#
	# process each recipient address individually
	#
	foreach my $msg_recipient (@{$permsgstatus->{msg_recipients}}) {

		#
		# see if we're already at the limit
		#
		if ($self->{recipient_limit} != 0) {

			if ($self->{recipient_limit} ==
				$permsgstatus->{msg_recipient_count}) {

				dbg ("LDAPfilter\: maximum number of message " .
					"recipients searched ... skipping");

				last;
			}
		}

		#
		# purge any leftover data that might be around
		#
		undef $permsgstatus->{raw_resource_name};
		undef $permsgstatus->{ldap_resource_name};
		undef $permsgstatus->{ldap_search_result};
		undef $permsgstatus->{ldap_search_result_entry};
		undef $permsgstatus->{ldap_search_result_value};
		undef $permsgstatus->{ldap_search_result_match};

		#
		# set the resource name to the current recipient
		#
		$permsgstatus->{raw_resource_name} = $msg_recipient;

		#
		# clean the input data
		#
		chomp ($permsgstatus->{raw_resource_name});

		$permsgstatus->{raw_resource_name} =~ s/^\s+//;
		$permsgstatus->{raw_resource_name} =~ s/\s+$//;

		#
		# if it's null, skip it
		#
		if ($permsgstatus->{raw_resource_name} eq "") {

			next;
		}

		#
		# run it through the normalizer
		#
		$permsgstatus->{raw_resource_name} =
			normalize_email_address($permsgstatus->{raw_resource_name});

		#
		# see if it's a valid address
		#
		if (($self->{verify_resources} =~ /^on$/i) &&
			(verify_email_address($permsgstatus->{raw_resource_name}) == 0)) {

			dbg ("LDAPfilter\: \"" . $permsgstatus->{raw_resource_name} . "\"" .
				" is not a valid message recipient address ... skipping");

			next;
		}

		#
		# see if the recipient domain filter is set
		#
		if ($self->{recipient_filter} ne "") {

			#
			# test for simple mis-matches
			#
			if ($self->{recipient_filter} ne
				substr($permsgstatus->{raw_resource_name},
				-(length($self->{recipient_filter})))) {

				#
				# recipient isn't in the filter domain, skip it
				#
				dbg ("LDAPfilter\: RFC822 message recipient address " .
					"\"" . $permsgstatus->{raw_resource_name} . "\"" .
					" not in filter ... skipping");

				next;
			}

			#
			# test for label boundaries ("ibm.com" =! "fibm.com")
			#
			if (! substr($permsgstatus->{raw_resource_name},
				-(length($self->{recipient_filter})),
				-1) =~ /[\@|\.]/) {

				#
				# recipient isn't in the filter domain, skip it
				#
				dbg ("LDAPfilter\: RFC822 message recipient address " .
					"\"" . $permsgstatus->{raw_resource_name} . "\"" .
					" not in filter ... skipping");

				next;
			}
		}

		#
		# increment the recipient count
		#
		$permsgstatus->{msg_recipient_count}++;

		#
		# copy the seed resource name for ldap lookups
		#
		$permsgstatus->{ldap_resource_name} = $permsgstatus->{raw_resource_name};

		#
		# prepare the search data
		#
		dbg ("LDAPfilter\: RFC822 message recipient address determined as " .
			"\"" . $permsgstatus->{ldap_resource_name} . "\"");

		$permsgstatus->{ldap_resource_attr} = $self->{ldap_msg_tocc_attr};

		#
		# execute the search and exit if we get a hard return
		#
		if ($self->generate_ldap_search($permsgstatus) == 0) {

			return 0;
		}

		#
		# skip this recipient if the search didn't produce results
		#
		if (! defined $permsgstatus->{ldap_search_result_value}) {

			next;
		}

		#
		# we got results
		#
		else {
			if ($permsgstatus->{ldap_search_result_blacklisted} == 1) {
				$permsgstatus->{msg_tocc_blacklisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_darklisted} == 1) {
				$permsgstatus->{msg_tocc_darklisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_lightlisted} == 1) {
				$permsgstatus->{msg_tocc_lightlisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_whitelisted} == 1) {
				$permsgstatus->{msg_tocc_whitelisted} = 1;
			}

			#
			# move to the next recipient address
			#
			next;
		}
	}

	#
	# go back to the main loop
	#
	return 1;
}

sub look_for_msg_uri {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# purge any leftover data that might be around
	#
	undef $permsgstatus->{raw_resource_name};
	undef $permsgstatus->{ldap_resource_name};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	#
	# see if we should be here
	#
	if ($self->{search_msg_uri} =~ /off/i) {

		dbg ("LDAPfilter\: RFC822 message body URI searches " .
			"disabled ... skipping");

		return 1;
	}

	#
	# create and populate an array of http and mailto URIs
	#
	@{$permsgstatus->{msg_uris}} =
		grep { /^(ftp\:|http(s?)\:|mailto\:)/i }
		$permsgstatus->get_uri_list();

	if (@{$permsgstatus->{msg_uris}} == 0) {

		dbg ("LDAPfilter\: RFC822 message body does not contain any URIs " .
			" ... skipping");

		return 1;
	}

	#
	# start a counter for the URI limit
	#
	$permsgstatus->{msg_uri_count} = 0;

	#
	# process each URI address individually
	#
	foreach my $msg_uri (@{$permsgstatus->{msg_uris}}) {

		#
		# see if we're already at the limit
		#
		if ($self->{uri_limit} != 0) {

			if ($self->{uri_limit} ==
				$permsgstatus->{msg_uri_count}) {

				dbg ("LDAPfilter\: maximum number of message " .
					"URIs searched ... skipping");

				last;
			}
		}

		#
		# purge any leftover data that might be around
		#
		undef $permsgstatus->{raw_resource_name};
		undef $permsgstatus->{ldap_resource_name};
		undef $permsgstatus->{ldap_search_result};
		undef $permsgstatus->{ldap_search_result_entry};
		undef $permsgstatus->{ldap_search_result_value};
		undef $permsgstatus->{ldap_search_result_match};

		#
		# set the resource name to the current uri
		#
		$permsgstatus->{raw_resource_name} = $msg_uri;

		#
		# clean the input data
		#
		chomp ($permsgstatus->{raw_resource_name});

		$permsgstatus->{raw_resource_name} =~ s/^\s+//;
		$permsgstatus->{raw_resource_name} =~ s/\s+$//;

		#
		# if it's null, skip it
		#
		if ($permsgstatus->{raw_resource_name} eq "") {

			next;
		}

		#
		# see if it's a valid URI
		#
		if (($self->{verify_resources} =~ /^on$/i) &&
			(verify_uri_address($permsgstatus->{raw_resource_name}) == 0)) {

			dbg ("LDAPfilter\: \"" . $permsgstatus->{raw_resource_name} . "\"" .
				" is not a valid URI ... skipping");

			next;
		}

		#
		# increment the URI count
		#
		$permsgstatus->{msg_uri_count}++;

		#
		# copy the seed resource name for ldap lookups
		#
		$permsgstatus->{ldap_resource_name} = $permsgstatus->{raw_resource_name};

		#
		# prepare the search data
		#
		dbg ("LDAPfilter\: RFC822 message body URI determined as " .
			"\"" . $permsgstatus->{ldap_resource_name} . "\"");

		$permsgstatus->{ldap_resource_attr} = $self->{ldap_msg_uri_attr};

		#
		# execute the search and exit if we get a hard return
		#
		if ($self->generate_ldap_search($permsgstatus) == 0) {

			return 0;
		}

		#
		# skip this URI if the search didn't produce results
		#
		if (! defined $permsgstatus->{ldap_search_result_value}) {

			next;
		}

		#
		# we got results
		#
		else {
			if ($permsgstatus->{ldap_search_result_blacklisted} == 1) {
				$permsgstatus->{msg_uri_blacklisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_darklisted} == 1) {
				$permsgstatus->{msg_uri_darklisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_lightlisted} == 1) {
				$permsgstatus->{msg_uri_lightlisted} = 1;
			}

			if ($permsgstatus->{ldap_search_result_whitelisted} == 1) {
				$permsgstatus->{msg_uri_whitelisted} = 1;
			}

			#
			# move to the next URI
			#
			next;
		}
	}

	#
	# go back to the main loop
	#
	return 1;
}

#
# establish a connection, login, and look for naming context if needed
#
sub create_ldap_session {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# clean up any junk that might be leftover from earlier attempts
	#
	undef $self->{ldap_session};
	undef $self->{ldap_session_uri};
	undef $self->{ldap_session_login};
	undef $self->{ldap_naming_context};

	#
	# tell the user what we're doing
	#
	dbg ("LDAPfilter\: LDAP session does not exist ... connecting");

	#
	# connect with the LDAP sever using the named protocol
	#
	if ($self->{ldap_transport} =~ /^ldap$/i) {

		eval {require Net::LDAP};

		if ($@) {

			dbg ("LDAPfilter\: Net::LDAP module unavailable, " .
				"cannot proceed ... terminating");

			return 0;
		}

		use Net::LDAP;

		#
		# if an LDAP server isn't defined, try to find one with SRV
		#
		if ($self->{ldap_server} eq "") {

			dbg ("LDAPfilter\:   no LDAP server specified " .
				"... attempting to locate available servers");

			#
			# call the SRV lookup function, and exit on failure
			#
			if ($self->locate_ldap_server($permsgstatus) == 0) {

				return 0;
			}

			#
			# try each of the discovered servers in sequence
			#
			$self->{ldap_srv_count} = 0;

			foreach (@{$self->{ldap_srv_answers}}) {

				#
				# if it's the root domain, skip it
				#
				if ($self->{ldap_srv_answers}[$self->{ldap_srv_count}]->target eq "") {

					dbg ("LDAPfilter\:   received empty LDAP server name " .
						"... skipping");

					next;
				}

				my $ldap_server = $self->{ldap_srv_answers}[$self->{ldap_srv_count}]->target;

				my $ldap_port = $self->{ldap_srv_answers}[$self->{ldap_srv_count}]->port;

				#
				# untaint and verify the domain name
				#
				if ($ldap_server =~ /^(\S+)$/) {

					$ldap_server = $1;

					chomp ($ldap_server);

					if (verify_domain_name($ldap_server) == 0) {

						dbg ("LDAPfilter\:   received invalid LDAP server name \"" .
							$ldap_server . "\" ... skipping");

						$self->{ldap_srv_count}++;

						next;
					}
				}

				else {
					dbg ("LDAPfilter\:   received invalid LDAP server name \"" .
						$ldap_server . "\" ... skipping");

					$self->{ldap_srv_count}++;

					next;
				}

				#
				# untaint and verify the port number
				#
				if ($ldap_port =~ /^(\d+)$/) {

					$ldap_port = $1;

					chomp ($ldap_port);

					if (($ldap_port < 1) || ($ldap_port > 65535)) {

						dbg ("LDAPfilter\:   received invalid LDAP port number \"" .
							$ldap_port . "\" ... skipping");

						$self->{ldap_srv_count}++;

						next;
					}
				}

				else {
					dbg ("LDAPfilter\:   received invalid LDAP port number \"" .
						$ldap_port . "\" ... skipping");

					$self->{ldap_srv_count}++;

					next;
				}

				#
				# everything passed, so try this entry
				#
				$self->{ldap_server} = $ldap_server;
				$self->{ldap_port} = $ldap_port;

				dbg ("LDAPfilter:   preferred server is " .
					$self->{ldap_server} . "\:" . $self->{ldap_port} );

				#
				# try to make the connection
				#
				$self->{ldap_session} = Net::LDAP->new(
					$self->{ldap_server},
					port => $self->{ldap_port},
					version => $self->{ldap_version},
					timeout => $self->{ldap_timeout});

				#
				# see if the connect operation failed
				#
				if (! defined $self->{ldap_session}) {

					dbg ("LDAPfilter\:   could not connect to \"" .
						$self->{ldap_server} . "\:" .
						$self->{ldap_port} . "\" ... skipping");

					$self->{ldap_srv_count}++;

					next;
				}

				#
				# connect succeeded
				#
				dbg ("LDAPfilter\:   connect succeeded for $self->{ldap_session_uri}");

				#
				# define a URI for later reuse
				#
				$self->{ldap_session_uri} = $self->{ldap_transport} . "\:\/\/" .
					$self->{ldap_server} . "\:" . $self->{ldap_port} . "\/";

				#
				# perform the login operation
				#
				if ($self->bind_ldap_session($permsgstatus) == 0) {

					$self->destroy_ldap_session($permsgstatus);

					$self->{ldap_srv_count}++;

					next;
				}

				#
				# probe for the naming context
				#
				if ($self->probe_ldap_context($permsgstatus) == 0) {

					$self->destroy_ldap_session($permsgstatus);

					$self->{ldap_srv_count}++;

					next;
				}

				#
				# probe the search base to see if things are working
				#
				if ($self->test_ldap_session($permsgstatus) == 0) {

					$self->destroy_ldap_session($permsgstatus);

					$self->{ldap_srv_count}++;

					next;
				}

				#
				# everything passed, so break out of the loop
				#
				last;
			}
		}

		#
		# LDAP server was manually defined
		#
		else {
			#
			# if a port number wasn't found, use the default value
			#
			if ($self->{ldap_port} eq "") {

				$self->{ldap_port} = 389;
			}

			#
			# try to make the connection
			#
			$self->{ldap_session} = Net::LDAP->new(
				$self->{ldap_server},
				port => $self->{ldap_port},
				version => $self->{ldap_version},
				timeout => $self->{ldap_timeout});

			#
			# see if the connect operation failed
			#
			if (! defined $self->{ldap_session}) {

				dbg ("LDAPfilter\:   could not connect to \"" .
					$self->{ldap_server} . "\:" .
					$self->{ldap_port} . "\" ... skipping");
			}

			#
			# define a URI for later reuse
			#
			$self->{ldap_session_uri} = $self->{ldap_transport} . "\:\/\/" .
				$self->{ldap_server} . "\:" . $self->{ldap_port} . "\/";

			#
			# connect succeeded
			#
			dbg ("LDAPfilter\:   connect succeeded for $self->{ldap_session_uri}");

			#
			# perform the login operation
			#
			if ($self->bind_ldap_session($permsgstatus) == 0) {

				$self->destroy_ldap_session($permsgstatus);
			}

			#
			# probe for the naming context
			#
			if ($self->probe_ldap_context($permsgstatus) == 0) {

				$self->destroy_ldap_session($permsgstatus);
			}

			#
			# probe the search base to see if things are working
			#
			if ($self->test_ldap_session($permsgstatus) == 0) {

				$self->destroy_ldap_session($permsgstatus);
			}
		}

		#
		# see if the operation(s) failed
		#
		if (! defined $self->{ldap_session}) {

			#
			# connect failed for some reason
			#
			dbg ("LDAPfilter\:   could not connect to any LDAP server" .
				" ... terminating");

			return 0;
		}

		#
		# report the success
		#
		dbg ("LDAPfilter\:   LDAP session successfully established ... continuing");

		return 1;
	}

	elsif ($self->{ldap_transport} =~ /^ldaps$/i) {

		eval {require Net::LDAPS};

		if ($@) {

			dbg ("LDAPfilter\: Net::LDAPS module unavailable, " .
				"cannot proceed ... terminating");

			return 0;
		}

		use Net::LDAPS;

		#
		# if a default port wasn't discovered, define one here
		#
		if ($self->{ldap_port} eq "") {

			$self->{ldap_port} = 636;
		}

		#
		# try to make the connection
		#
		$self->{ldap_session} = Net::LDAPS->new(
			$self->{ldap_server},
			port => $self->{ldap_port},
			verify => $self->{ldap_ssl_verify},
			capath => $self->{ldap_ssl_capath});

		#
		# define a URI for later reuse
		#
		$self->{ldap_session_uri} = $self->{ldap_transport} . "\:\/\/" .
			$self->{ldap_server} . "\:" . $self->{ldap_port} . "\/";

		#
		# connect succeeded
		#
		dbg ("LDAPfilter\:   connect succeeded for $self->{ldap_session_uri}");

		#
		# perform the login operation
		#
		if ($self->bind_ldap_session($permsgstatus) == 0) {

			$self->destroy_ldap_session($permsgstatus);
		}

		#
		# probe for the naming context
		#
		if ($self->probe_ldap_context($permsgstatus) == 0) {

			$self->destroy_ldap_session($permsgstatus);
		}

		#
		# probe the search base to see if things are working
		#
		if ($self->test_ldap_session($permsgstatus) == 0) {

			$self->destroy_ldap_session($permsgstatus);
		}

		#
		# see if the operation failed
		#
		if (! defined $self->{ldap_session}) {

			#
			# connect failed for some reason
			#
			dbg ("LDAPfilter\:   could not connect to " .
				$self->{ldap_session_uri} . " ... terminating");

			return 0;
		}

		#
		# report the success
		#
		dbg ("LDAPfilter\:   LDAP session successfully established ... continuing");

		return 1;
	}

	elsif ($self->{ldap_transport} =~ /^ldapi$/i) {

		eval {require Net::LDAPI};

		if ($@) {

			dbg ("LDAPfilter\: Net::LDAPI module unavailable, " .
				"cannot proceed ... terminating");

			return 0;
		}

		use Net::LDAPI;

		#
		# escape the path separators to work with URLs
		#
		my $ldapi_path = $self->{ldap_ldapi_path};

		$ldapi_path =~ s/\//\%2F/g;

		#
		# try to make the connection
		#
		$self->{ldap_session} = Net::LDAPI->new(
			$ldapi_path);

		#
		# define a URI for later reuse
		#
		$self->{ldap_session_uri} = $self->{ldap_transport} . "\:\/\/" .
			$ldapi_path . "\/";

		#
		# connect succeeded
		#
		dbg ("LDAPfilter\:   connect succeeded for $self->{ldap_session_uri}");

		#
		# perform the login operation
		#
		if ($self->bind_ldap_session($permsgstatus) == 0) {

			$self->destroy_ldap_session($permsgstatus);
		}

		#
		# probe for the naming context
		#
		if ($self->probe_ldap_context($permsgstatus) == 0) {

			$self->destroy_ldap_session($permsgstatus);
		}

		#
		# probe the search base to see if things are working
		#
		if ($self->test_ldap_session($permsgstatus) == 0) {

			$self->destroy_ldap_session($permsgstatus);
		}

		#
		# see if the operation failed
		#
		if (! defined $self->{ldap_session}) {

			#
			# connect failed for some reason
			#
			dbg ("LDAPfilter\:   could not connect to " .
				$self->{ldap_session_uri} . " ... terminating");

			return 0;
		}

		#
		# report the success
		#
		dbg ("LDAPfilter\:   LDAP session successfully established ... continuing");

		return 1;
	}

	#
	# transport method does not match any known types
	#
	else {
		dbg ("LDAPfilter\: unknown transport specified ... terminating");

		return 0;
	}
}

#
# try to locate the best LDAP server using SRV lookups
#
sub locate_ldap_server {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# see if Sys::Hostname::Long and Net::DNS are available
	#
	eval {require Sys::Hostname::Long};

	if ($@) {

		dbg ("LDAPfilter\:   Sys::Hostname::Long module " .
			"unavailable, cannot proceed ... terminating");

		return 0;
	}

	eval {
		require Net::DNS::Resolver;
		require Net::DNS::Packet;
		require Net::DNS::RR;
	};

	if ($@) {

		dbg ("LDAPfilter\:   Net::DNS modules are not " .
			"available ... terminating");

		return 0;
	}

	#
	# suck up the FQDN and verify that it has at least two dots
	#
	my $hostname = Sys::Hostname::Long->hostname_long;

	if (! $hostname =~ /\S+?\.(\S+?\.\S*)/) {

		dbg ("LDAPfilter\:   Unable to determine parent domain for " .
			"LDAP SRV record ... terminating");

		return 0;
	}

	#
	# extract the parent domain from the FQDN
	#
	my $srv_domain = strip_resource_name($hostname);

	#
	# see if it's a valid domain name
	#
	if (verify_domain_name($srv_domain) == 0) {

		dbg ("LDAPfilter\:   Unable to determine parent domain for " .
			"LDAP SRV record ... terminating");

		return 0;
	}

	#
	# define the SRV name, including any needed trailing dot
	#
	$srv_domain = "_ldap._tcp." . $srv_domain;

	if (! $srv_domain =~ /\.$/) {

		$srv_domain = $srv_domain . ".";
	}

	#
	# make the resolver instance
	#
	my $srv_resolver = Net::DNS::Resolver->new;

	#
	# see if the resolver was created successfully
	#
	if (! defined $srv_resolver) {

		dbg ("LDAPfilter\:   Unable to create DNS resolver instance for " .
			"LDAP SRV queries ... terminating");

		return 0;
	}

	#
	# issue the query for the SRV RRs
	#
	my $srv_lookup = "";

	eval {
		local $SIG{ALRM} = sub { die "dns query timeout" };

		alarm $self->{ldap_timeout};

		$srv_lookup = $srv_resolver->send($srv_domain, "SRV");

		alarm 0;
	};

	#
	# see if there was an answer
	#
	if (! defined $srv_lookup) {

		dbg ("LDAPfilter\:   Unable to query for LDAP SRV record " .
			"... terminating");

		return 0;
	}

	#
	# see if any RRs were returned
	#
	if ($srv_lookup->header->ancount == 0) {

		dbg ("LDAPfilter\:   No DNS resource records were returned " .
			"... terminating");

		return 0;
	}

	#
	# create an array of the answer's SRV RRs
	#
	my @srv_answers = grep { $_->type eq 'SRV' } $srv_lookup->answer;

	#
	# see if any SRV RRs were returned
	#
	if (@srv_answers == 0) {

		dbg ("LDAPfilter\:   No SRV resource records were returned " .
			"... terminating");

		return 0;
	}

	#
	# sort the array by the value returned from Net::DNS::RR::SRV 'priority' method
	#
	@srv_answers = sort { $a->priority <=> $b->priority } @srv_answers;

	@{$self->{ldap_srv_answers}} = @srv_answers;

	#
	# return to the calling function
	#
	dbg ("LDAPfilter\:   discovered " . @srv_answers . " LDAP servers");

	return 1;
}

#
# login to activate the current LDAP session
#
sub bind_ldap_session {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# bind to the server
	#
	if ($self->{ldap_bind_dn} eq "") {
		$self->{ldap_session_login} = $self->{ldap_session}->bind();
	}

	else {
		$self->{ldap_session_login} = $self->{ldap_session}->bind( 
			$self->{ldap_bind_dn},
			password => $self->{ldap_bind_password} );
	}

	#
	# see if the login operation failed
	#
	if ($self->{ldap_session_login}->code() != 0) {

		#
		# login failed, report the error
		#
		dbg ("LDAPfilter\:   bind failed with " .
			"\"" . $self->{ldap_session_login}->error . "\"");

		return 0;
	}

	#
	# the login succeeded
	#
	if ($self->{ldap_bind_dn} eq "") {
		dbg ("LDAPfilter\:   bind succeeded as anonymous");
	}

	else {
		dbg ("LDAPfilter\:   bind succeeded for ".
			"\"$self->{ldap_bind_dn}\"");
	}

	#
	# return to the calling function
	#
	return 1;
}

#
# probe the LDAP session to make sure it's working
#
sub probe_ldap_context {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# see if we need to locate a naming context
	#
	if ($self->{ldap_search_base} eq "") {

		dbg ("LDAPfilter\:   no LDAP search base specified " .
			"... attempting to use default naming context");

		#
		# try to read the root DSE object
		#
		my $ldap_root_dse = $self->{ldap_session}->root_dse;

		if ((!defined $ldap_root_dse) ||
			($ldap_root_dse eq "")) {

			dbg ("LDAPfilter\:   unable to read the root DSE object");

			return 0;
		}

		#
		# try to read the namingContexts entry
		#
		my $ldap_naming_context = $ldap_root_dse->get_value('namingContexts');

		#
		# see if we got a naming context
		#
		if ((!defined $ldap_naming_context) ||
			($ldap_naming_context eq "")) {

			dbg ("LDAPfilter\:   unable to determine the default naming context");

			return 0;
		}

		#
		# make the naming context our search base
		#
		else {
			dbg ("LDAPfilter\:   using naming context value of " .
				"\"" . $ldap_naming_context . "\"");

			$self->{ldap_search_base} = $ldap_naming_context;
		}
	}

	#
	# return to the calling function
	#
	return 1;
}

#
# issue a probe query to the search base DN, and barf on error
#
sub test_ldap_session {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# clear out any leftover junk
	#
	undef $self->{ldap_session_probe};

	#
	# issue the probe search
	#
	eval {
		local $SIG{ALRM} = sub { die "ldap query timeout" };

		alarm $self->{ldap_timeout};

		$self->{ldap_session_probe} = $self->{ldap_session}->search(
			base => $self->{ldap_search_base},
			filter => '(objectclass=*)',
			scope => 'base',
			deref => 'never',
			timelimit => $self->{ldap_timeout},
			attrs => ['objectClass']);

		alarm 0;
	};

	#
	# see if the probe had ANY problems
	#
	if ((! defined $self->{ldap_session_probe}) ||
		($self->{ldap_session_probe}->code() != 0)) {

		#
		# report the error if it's defined
		#
		if (defined $self->{ldap_session_probe}) {

			dbg ("LDAPfilter\:   LDAP probe failed with " .
				"\"" . $self->{ldap_session_probe}->error . "\"");
		}

		return 0;
	}
	
	#
	# successfully probed the session
	#
	my $search_base = $self->{ldap_search_base};

	$search_base =~ s/\s/\%20/g;

	dbg ("LDAPfilter\:   probe succeeded for " .
		$self->{ldap_session_uri} . $search_base . "/");

	undef $search_base;

	return 1;
}

#
# build the search for the named resource
#
sub generate_ldap_search {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# clear out any leftover junk
	#
	undef $permsgstatus->{ldap_search_filter};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	$permsgstatus->{ldap_search_result_blacklisted} = 0;
	$permsgstatus->{ldap_search_result_darklisted} = 0;
	$permsgstatus->{ldap_search_result_lightlisted} = 0;
	$permsgstatus->{ldap_search_result_whitelisted} = 0;

	#
	# start a counter for any recursion limits that may be defined
	#
	# use -1 because this is a recursion counter, not a search counter
	#
	$permsgstatus->{recursion_count} = -1;

	#
	# build a single search filter for the resource hierarchy
	#
	if ($self->{ldap_search_mode} =~ /batch/i) {

		#
		# seed the search filter string with a leading parenthesis and an 'OR' symbol
		#
		$permsgstatus->{ldap_search_filter} = "(|";

		#
		# add each resource from the hierarchy to the search filter
		#
		while ($permsgstatus->{ldap_resource_name} ne "") {

			#
			# see if a recursion limit is defined
			#
			if ($self->{recursion_limit} != 0) {

				#
				# see if we're at the limit already
				#
				if ($self->{recursion_limit} ==
					$permsgstatus->{recursion_count}) {

					dbg ("LDAPfilter\: reached the maximum recursion limit " .
						"... cancelling further analysis");

					$permsgstatus->{ldap_resource_name} = "";

					last;
				}
			}

			#
			# increment the current recursion count
			#
			$permsgstatus->{recursion_count}++;

			#
			# look for any type-specific attribute definition
			#
			$self->check_resource_type($permsgstatus);

			#
			# add the current resource to the search filter string
			#
			$permsgstatus->{ldap_search_filter} =
				$permsgstatus->{ldap_search_filter} . "(" .
				$permsgstatus->{ldap_search_match_attr} . "=" .
				$permsgstatus->{ldap_resource_name} . ")";

			#
			# strip the leading element from the resource name and restart
			#
			if ($permsgstatus->{ldap_resource_name} =~ /\./) {

				$permsgstatus->{ldap_resource_name} =
					strip_resource_name($permsgstatus->{ldap_resource_name});

				next;
			}

			#
			# no more delegation parents, so exit out
			#
			else {
				$permsgstatus->{ldap_resource_name} = "";

				last;
			}
		}

		#
		# terminate the search filter string with a closing parenthesis
		#
		$permsgstatus->{ldap_search_filter} =
			$permsgstatus->{ldap_search_filter} . ")";

		#
		# issue the search and return accordingly
		#
		if ($self->process_ldap_search($permsgstatus) == 0) {

			return 0;
		}

		else {
			return 1;
		}
	}

	#
	# build individual search filters for each resource in the hierarchy
	#
	else {
		#
		# try the search until all the name elements are exhausted
		#
		while ($permsgstatus->{ldap_resource_name} ne "") {

			#
			# see if a recursion limit is defined
			#
			if ($self->{recursion_limit} != 0) {

				#
				# see if we're at the limit already
				#
				if ($self->{ldap_search_recursion} ==
					$permsgstatus->{recursion_count}) {
	
					dbg ("LDAPfilter\: reached the maximum recursion limit " .
						"... cancelling further analysis");

					return 1;
				}
			}

			#
			# increment the current recursion count
			#
			$permsgstatus->{recursion_count}++;

			#
			# look for any type-specific attribute definition
			#
			$self->check_resource_type($permsgstatus);

			#
			# build the search filter
			#
			$permsgstatus->{ldap_search_filter} = "(" .
				$permsgstatus->{ldap_search_match_attr} . "=" .
				$permsgstatus->{ldap_resource_name} . ")";

			#
			# issue the search and return if there was an error
			#
			if ($self->process_ldap_search($permsgstatus) == 0) {

				return 0;
			}

			#
			# no errors, so strip the leading element and restart
			#
			if ($permsgstatus->{ldap_resource_name} =~ /\./) {

				$permsgstatus->{ldap_resource_name} =
					strip_resource_name($permsgstatus->{ldap_resource_name});

				$permsgstatus->{ldap_search_filter} =
					"($permsgstatus->{ldap_search_match_attr} = " .
					"$permsgstatus->{ldap_resource_name})";

				next;
			}

			#
			# no more delegation parents to try so exit gracefully
			#
			else {
				$permsgstatus->{ldap_resource_name} = "";

				return 1;
			}
		}
	}
}

#
# issue and process the individual LDAP searches
#
sub process_ldap_search {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# post a notice about the search
	#
	dbg ("LDAPfilter\:   searching for " .
		$permsgstatus->{ldap_search_filter});

	#
	# issue the LDAP search
	#
	eval {
		local $SIG{ALRM} = sub { die "alarm clock restart" };
		alarm $self->{ldap_timeout};

		$permsgstatus->{ldap_search_result} = $self->{ldap_session}->search(
			base => $self->{ldap_search_base},
			filter => $permsgstatus->{ldap_search_filter},
			scope => $self->{ldap_search_scope},
			deref => $self->{ldap_search_deref},
			timelimit => $self->{ldap_timeout},
			attrs => [$permsgstatus->{ldap_resource_attr}]);

		alarm 0;
	};

	#
	# see if the timeout triggered
	#
	if ($@ and $@ !~ /alarm clock restart/) {

		dbg ("LDAPfilter\:   search timed out ... aborting");

		#
		# disconnect the session politely
		#
		dbg ("LDAPfilter\: unable to proceed ... terminating");

		$self->destroy_ldap_session($permsgstatus);

		return 0;
	}

	#
	# see if there was a problem
	#
	if ((! defined $permsgstatus->{ldap_search_result}) ||
		($permsgstatus->{ldap_search_result}->code() != 0)) {

		#
		# report the error if it's defined
		#
		if (defined $permsgstatus->{ldap_search_result}) {

			dbg ("LDAPfilter\:   search failed with " .
				"\"" . $permsgstatus->{ldap_search_result}->error . "\"");
		}

		#
		# disconnect the session politely
		#
		dbg ("LDAPfilter\: unable to proceed ... terminating");

		$self->destroy_ldap_session($permsgstatus);

		#
		# return the failure
		#
		return 0;
	}

	#
	# see if the named resource doesn't have an entry
	#
	if ($permsgstatus->{ldap_search_result}->count == "0") {

		dbg ("LDAPfilter\:   no entries were returned");

		$permsgstatus->{ldap_search_result_match} = 0;

		return 1;
	}

	#
	# at least one entry, cycle through to see if they have the named attribute
	#
	foreach my $entry_count (0 .. ($permsgstatus->{ldap_search_result}->count -1)) {

		$permsgstatus->{ldap_search_result_entry} =
			$permsgstatus->{ldap_search_result}->entry($entry_count);

		#
		# if the current entry does not have the named attribute, try the next one
		#
		if ($permsgstatus->{ldap_search_result_entry}->exists(
			$permsgstatus->{ldap_resource_attr}) != 1) {

			dbg ("LDAPfilter\:   \"" .
				substr($permsgstatus->{ldap_search_result_entry}->dn(),0,40) . "...\" " .
				"does not have a $permsgstatus->{ldap_resource_attr} attribute");

			$permsgstatus->{ldap_search_result_match} = 0;

			next;
		}

		#
		# the entry has the named attribute ... we have a winner
		#
		else {
			$permsgstatus->{ldap_search_result_value} =
				$permsgstatus->{ldap_search_result_entry}->get_value(
					$permsgstatus->{ldap_resource_attr});

			#
			# tell them what they've won
			#
			if ($permsgstatus->{ldap_search_result_value} eq
				$self->{ldap_blacklist_val}) {

				dbg ("LDAPfilter\:   \"" .
					substr($permsgstatus->{ldap_search_result_entry}->dn(),0,40) . "...\" " .
					"has a $permsgstatus->{ldap_resource_attr} attribute with " .
					"the value of $permsgstatus->{ldap_search_result_value}");

				$permsgstatus->{ldap_search_result_blacklisted} = 1;
			}

			elsif ($permsgstatus->{ldap_search_result_value} eq
				$self->{ldap_darklist_val}) {
		
				dbg ("LDAPfilter\:   \"" .
					substr($permsgstatus->{ldap_search_result_entry}->dn(),0,40) . "...\" " .
					"has a $permsgstatus->{ldap_resource_attr} attribute with " .
					"the value of $permsgstatus->{ldap_search_result_value}");

				$permsgstatus->{ldap_search_result_darklisted} = 1;
			}

			elsif ($permsgstatus->{ldap_search_result_value} eq
				$self->{ldap_lightlist_val}) {

				dbg ("LDAPfilter\:   \"" .
					substr($permsgstatus->{ldap_search_result_entry}->dn(),0,40) . "...\" " .
					"has a $permsgstatus->{ldap_resource_attr} attribute with " .
					"the value of $permsgstatus->{ldap_search_result_value}");

				$permsgstatus->{ldap_search_result_lightlisted} = 1;
			}
		
			elsif ($permsgstatus->{ldap_search_result_value} eq
				$self->{ldap_whitelist_val}) {

				dbg ("LDAPfilter\:   \"" .
					substr($permsgstatus->{ldap_search_result_entry}->dn(),0,40) . "...\" " .
					"has a $permsgstatus->{ldap_resource_attr} attribute with " .
					"the value of $permsgstatus->{ldap_search_result_value}");

				$permsgstatus->{ldap_search_result_whitelisted} = 1;
			}

			else {
				dbg ("LDAPfilter\:   \"" .
					substr($permsgstatus->{ldap_search_result_entry}->dn(),0,40) . "...\" " .
					"has a $permsgstatus->{ldap_resource_attr} attribute with " .
					"the unknown value " .
					"\"$permsgstatus->{ldap_search_result_value}\"");
			}

			$permsgstatus->{ldap_search_result_match} = 1;

			#
			# see if any of the other entries have attributes too
			#
			next;
		}
	}

	#
	# all done with this search, so let's go back
	#
	return 1;
}

#
# tear-down the LDAP session
#
sub destroy_ldap_session {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# logout and clear the session flag
	#
	if (defined $self->{ldap_session}) {

		$self->{ldap_logout} = $self->{ldap_session}->unbind;

		dbg ("LDAPfilter\:   LDAP session disconnected from $self->{ldap_session_uri}");

		undef $self->{ldap_session};
	}
}

#
# try to determine the resource type, and then see if the user has
# defined any resource-specific attributes for that type
#
sub check_resource_type {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# see if it's a URI
	#
	if ($permsgstatus->{ldap_resource_name} =~ /^(ftp\:|http(s?)\:|mailto\:)/i) {

		if ($self->{ldap_uri_match_attr} ne "") {

			$permsgstatus->{ldap_search_match_attr} =
				$self->{ldap_uri_match_attr};
		}

		else {
			$permsgstatus->{ldap_search_match_attr} =
				$self->{ldap_match_attr};
		}
	}

	#
	# see if it's an email address
	#
	if ($permsgstatus->{ldap_resource_name} =~ /\@/) {

		if ($self->{ldap_email_match_attr} ne "") {

			$permsgstatus->{ldap_search_match_attr} =
				$self->{ldap_email_match_attr};
		}

		else {
			$permsgstatus->{ldap_search_match_attr} =
				$self->{ldap_match_attr};
		}
	}

	#
	# see if it's a raw IP address
	#
	elsif ($permsgstatus->{ldap_resource_name} =~ /^[\/\d\.]+$/) {

		if ($self->{ldap_ip_match_attr} ne "") {

			$permsgstatus->{ldap_search_match_attr} =
				$self->{ldap_ip_match_attr};
		}

		else {
			$permsgstatus->{ldap_search_match_attr} =
				$self->{ldap_match_attr};
		}
	}

	#
	# it must be a domain name or literal
	#
	else {
		if ($self->{ldap_dns_match_attr} ne "") {

			$permsgstatus->{ldap_search_match_attr} =
				$self->{ldap_dns_match_attr};
		}

		else {
			$permsgstatus->{ldap_search_match_attr} =
				$self->{ldap_match_attr};
		}
	}

	return;
}

#
# strip off the least-significant resource name element
#
sub strip_resource_name {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# strip various elements from http: URIs (only look at URIs with path elements)
	#
	if ($_[0] =~ /^(ftp\:|http(s?)\:)(\/*)(\S+\@)?([a-z\d\-\.]+)(\:\d+)?(\/+\S*)/i) {

		my $http_method = $1;

		if (! defined $http_method) {

			$http_method = "";
		}

		my $http_separator = $3;

		if (! defined $http_separator) {

			$http_separator = "";
		}

		my $http_auth = $4;

		if (! defined $http_auth) {

			$http_auth = "";
		}

		my $http_domain = $5;

		if (! defined $http_domain) {

			$http_domain = "";
		}

		my $http_port = $6;

		if (! defined $http_port) {

			$http_port = "";
		}

		my $http_path = $7;

		if (! defined $http_path) {

			$http_path = "";
		}

		#
		# path is nested, so strip off last element
		#
		if ($http_path =~ /^(\S+)\/\S+$/) {

			$http_path = $1;

			return ($http_method .
				$http_separator .
				$http_auth .
				$http_domain .
				$http_port .
				$http_path .
				"\/");
		}

		#
		# path is single (non-terminal), so replace with terminal slash
		#
		if ($http_path =~ /^(\S+)\/$/) {

			return ($http_method .
				$http_separator .
				$http_auth .
				$http_domain .
				$http_port .
				"\/");
		}

		#
		# remove embedded authentication info
		#
		if ($http_auth ne "") {

			return ($http_method .
				$http_separator .
				$http_domain .
				$http_port .
				"\/");
		}

		#
		# remove embedded port number
		#
		if ($http_port ne "") {

			return ($http_method .
				$http_separator .
				$http_domain .
				"\/");
		}

		#
		# nothing left, so return bare tag and domain pair
		#
		return ($http_method .
			$http_separator .
			$http_domain);
	}

	#
	# remove ftp:/http(s): tag from pathless URIs to produce regular domain names
	#
	if ($_[0] =~ /^(ftp\:|http(s?)\:)(\/*)([a-z\d\-\.]+)$/i) {

		return ($4);
	}

	#
	# remove mailto: tag from URIs to produce regular email addresses
	#
	if ($_[0] =~ /^mailto\:(\S*)$/i) {

		return ($1);
	}

	#
	# remove angled brackets from email addresses
	#
	if ($_[0] =~ /^\<(.*)\>$/) {

		return ($1);
	}

	#
	# remove localpart element from email addresses
	#
	if ($_[0] =~ /\@(\S+)/) {

		my $mail_domain = $1;

		#
		# email addresses require literals, but trap raw IP addresses anyway
		#
		if ($mail_domain =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) {

			$mail_domain = $mail_domain . "/32";
		}

		return ($mail_domain);
	}

	#
	# remove brackets from address literals
	#
	if ($_[0] =~ /^\[([\d\.]+)\]$/) {

		#
		# read the current IP address
		#
		my $ip_address = $1;

		#
		# see if we are using CIDR
		#
		if ($self->{cidr_lookups} =~ /on/i) {

			return ($ip_address . "/32");
		}

		else {
			return ($ip_address);
		}
	}

	#
	# determine the possible IPv4 parent delegations
	#
	if ($_[0] =~ /^([\d\.]+)\/(\d{1,2})$/) {

		#
		# read the current IP address and CIDR prefix
		#
		my $ip_address = $1;
		my $ip_prefix = $2;

		#
		# set the starting prefix to /29
		#
		if ($ip_prefix == 32) {

			$ip_prefix = "29";
		}

		#
		# return an empty string if we've reached the largest delegation
		#
		elsif ($ip_prefix == 8) {

			return ("");
		}

		#
		# we're somewhere between /29 and /8 so subtract by one
		#
		else {
			$ip_prefix = ($ip_prefix - 1);
		}

		#
		# if we're still here, convert the current IP address into decimal form
		#
		my @ip_network = split (/\./, $ip_address);

		$ip_address = (((($ip_network[0] * 256) * 256) * 256) + 
			(($ip_network[1] * 256) * 256) +
			($ip_network[2] * 256) +
			$ip_network[3]);

		#
		# create a subnet mask for the current prefix
		#
		my $ip_subnet = oct("0b" . 
			("1" x $ip_prefix) . 
			("0" x (32 - $ip_prefix)));

		#
		# use AND matching to generate the network address
		#
		$ip_address = ($ip_address & $ip_subnet);

		#
		# convert the network address back to dotted-quad
		#
		$ip_address = sprintf("0x%x", $ip_address);

		$ip_address = substr($ip_address,-8,8);

		$ip_address = ( hex (substr($ip_address,0,2)) . "." .
			hex (substr($ip_address,2,2)) . "." .
			hex (substr($ip_address,4,2)) . "." .
			hex (substr($ip_address,6,2)) );

		#
		# return the calculated IP address and CIDR prefix
		#
		return ($ip_address . "/" . $ip_prefix);
	}

	#
	# remove trailing octet from IPv4 address
	#
	if ($_[0] =~ /^([\d\.]+)\.\d+$/) {

		return ($1);
	}

	#
	# remove leading label from domain name
	#
	if ($_[0] =~ /\.(\S+)/) {

		return ($1);
	}

	#
	# nothing left to remove, so return an empty string
	#
	return ("");
}

sub normalize_email_address {

	#
	# untaint the data before proceeding
	#
	my $mail_address = $_[0];

	#
	# check for the null envelope address and return it immediately
	#
	if ($mail_address eq "<>") {

		return ($mail_address);
	}

	#
	# replace embedded comments with a space
	#
	$mail_address =~ s/\(.*?\)/ /g;

        #
        # collapse any sequences of spaces
        #
	$mail_address =~ s/\s\s+/ /g;

	#
	# remove spaces around "." or "@" as per RFC 822
	#
	$mail_address =~ s/\s+\./\./g;
	$mail_address =~ s/\.\s+/\./g;
	$mail_address =~ s/\s+\@/\@/g;
	$mail_address =~ s/\@\s+/\@/g;

        #
        # strip off any surrounding spaces
        #
	$mail_address =~ s/^\s*//g;
	$mail_address =~ s/\s*$//g;

	#
	# if the Email::Address module is available, use it
	#
	eval {require Email::Address};

	if (! $@) {

		my @mail_addresses = Email::Address->parse($mail_address);

		if (! defined $mail_addresses[0]) {

			dbg ("LDAPfilter\: ***** Email::Address could not parse \"" .
				$_[0] . "\" ... ignoring *****");
		}

		else {
			$mail_address = $mail_addresses[0]->address;
		}
	}

	#
	# grab whatever is inside the angled brackets, if present
	#
	if ($mail_address =~ /^[^<]*?<(.*?)>.*$/) {

		$mail_address = $1;
	}

	#
	# all done, so return
	#
	return ($mail_address);
}

sub verify_ip_address {

	#
	# only allow numbers and dots
	#
	# prohibit leading, trailing, or multiple dots
	#
	if ((! $_[0] =~ /^(\d|\.)+$/) ||
		($_[0] =~ /^\./) ||
		($_[0] =~ /\.$/) ||
		($_[0] =~ /\.\./)) {

		return (0);
	}

	#
	# break the IP address into octets and verify each of them
	#
	my @ip_address = split(/\./, $_[0]);

	foreach my $ip_octet (@ip_address) {

		#
		# prohibit multi-digit octets that begin with zero
		#
		if ($ip_octet =~ /^0\d/) {

			return (0);
		}

		#
		# prohibit octests greater than 255
		#
		if ($ip_octet > 255 ) {

			return (0);
		}
	}

	#
	# everything passed, so return
	#
	return (1);
}

sub verify_domain_name {

	#
	# only allow letters, numbers, hyphens and dots
	#
	# prohibit leading, trailing or multiple dots
	#
	if ((! $_[0] =~ /^[a-z\d\-\.]+$/i) ||
		($_[0] =~ /^\./) ||
		($_[0] =~ /\.$/) ||
		($_[0] =~ /\.\./)) {

		return (0);
	}

	#
	# break the domain name into labels and verify each of them
	#
	my @dns_domain = split(/\./, $_[0]);

	foreach my $dns_label (@dns_domain) {

		#
		# prohibit a leading hyphen character
		#
		if (($dns_label =~ /^-/) ||
			($dns_label =~ /-$/)) {

			return (0);
		}
	}

	#
	# everything passed, so return
	#
	return (1);
}

sub verify_email_address {

	#
	# prohibit leading or trailing dots or "at" symbols
	#
	if (($_[0] =~ /^\./) ||
		($_[0] =~ /\.$/) ||
		($_[0] =~ /^\@/) ||
		($_[0] =~ /\@$/)) {

		return (0);
	}

	#
	# if the mail domain is an IP address, go ahead and verify it
	#
	if ($_[0] =~ /\@\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?(^>?)$/) {

		if (verify_ip_address($1) == 0) {

			return (0);
		}
	}

	#
	# if the mail domain isn't an IP address, verify it as a domain name
	#
	elsif ($_[0] =~ /\@(\S+)(^>?)$/) {

		if (verify_domain_name($1) == 0) {

			return (0);
		}
	}

	#
	# everything passed, so return
	#
	return (1);
}

sub verify_uri_address {

	#
	# prohibit spaces and forbidden characters
	#
	if (($_[0] =~ /^(\s*)$/) ||
		($_[0] =~ /[\s|\(|\)|\<|\>|\{|\}|\[|\]|\^|\||\\]/)) {

		return (0);
	}

	#
	# test the domain name in http URIs
	#
	if ($_[0] =~ /^(ftp\:|http(s?))\:(\/*)(\S+\@)?([a-z\d\-\.]+)(\:\d+)?(\/+\S*)?/i) {

		if (verify_domain_name($5) == 0) {

			return (0);
		}

	}

	#
	# test the email address in mailto URIs
	#
	elsif ($_[0] =~ /^mailto\:(\S+)$/i) {

		if (verify_email_address($1) == 0) {

			return (0);
		}
	}

	#
	# unknown or malformed URI, so reject it
	#
	else {
		return (0);
	}

	#
	# everything passed, so return
	#
	return (1);
}

#
# print debug messages
#
sub dbg {

	Mail::SpamAssassin::dbg (@_);
}

#
# object destructor block, called when SA exits
#
sub DESTROY {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# clear out the search flags
	#
	undef $permsgstatus->{ldap_resource_name};
	undef $permsgstatus->{ldap_search_result};
	undef $permsgstatus->{ldap_search_result_entry};
	undef $permsgstatus->{ldap_search_result_value};
	undef $permsgstatus->{ldap_search_result_match};

	#
	# see if a session is active
	#
	if (defined $self->{ldap_session}) {

		dbg ("***** DESTROY() killed the session *****");

		#
		# logout and clear the session flag
		#
		$self->{ldap_logout} = $self->{ldap_session}->unbind;

		dbg ("LDAPfilter\: LDAP session disconnected from $self->{ldap_session_uri}");

		undef $self->{ldap_session};
	}
}

1;

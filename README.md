# bindtool

Preprocessor for bind9 zone files.

This tool is useful for managing zone files for a bind9 DNS server.
It provides basic variable substitutions and automatic generation of several kinds of DNS records, in particular, those based on external resources, like public keys.
This greatly simplifies keeping DNS zones current when keys change as no zone files need to be edited.


## Installation

Requires Python3.7+.

    sudo pip3 install bindtool

Optionally create a virtual environment and install there.


### Configuration

The example configuration file lists all possible options and their defaults.
Only values that are different from the defaults need to be present.

The configuration file `bindtool.json` may be placed in the current working directory,
in /etc/bindtool,
or in the same directory as the bindtool tool is installed in.
A different configuration file name may be specified on the command line.
If the specified file name is not an absolute path,
it will be searched for in the same locations,
e.g. `bindtool --config config.json` will load `./config.json`, `/etc/bindtool/config.json`, or `<install-dir>/config.json`.
The file must adhere to standard JSON format.

Zone-specific config files may be placed along side the config file with the name `bindtoool.<zone-name>.json`.
If present, values in a zone-specific config file will override those in the config file when processing that zone.

#### Defaults

The `defaults` section specifies the default values for all of the arguments for the various record commands.

For example, to change the default `expire` value for SOA records::

    "defaults": {
        "soa": {
            "expire": "7d",
        }
    },
    ...


#### LDAP

The `ldap` section specifies the connection and search paramaters for LDAP records.

#### Directories

The `directories` section specifies the directories to find various file types in.

Directory values may include Python format strings for variable substitution.
All directory types accept the {name} field.
Certificate and private key directories also accept the {key_type}, {suffix}, and {username} fields.
The dkim directory accepts the {selector} and {domain} fields.


#### Key Type Suffixes

Each certificate and key file will have a suffix, just before the file extension,
indicating the type of key the file is for.

The default suffix used for each key type can be overridden in the `key_type_suffixes` section.
If you are only using a single key type, or want to omit the suffix from one key type,
set it to an empty string.
Note that if using multiple key types the suffix must be unique or files will be overridden.


#### File Names

All output file names can be overridden using standard Python format strings.
All file name types accept the {name} field.
Certificate and private key file names also accept the {key_type}, {suffix}, and {username} fields.
The dkim file name accepts the {selector} and {domain} fields.


## Usage

Run the command:

    bindtool <zone-file> [<output-directory-or-file>]

The tool will process the source zone file and output a zone file ready for use by the DNS server.

It is best to keep the source zone files in a different directory than the DNS server uses for its zone files.
For example, keep the source files in `/etc/bind/zones` and configure the DNS server to load the zone files from `/var/cache/bind`.
When making changes to a zone, edit the file in `/etc/bind/zones`, remove the server's journal file, and run the command:

    bindtool /etc/bind/zones/myzone.com /var/cache/bind

The script `reload-zone.sh` (provided in this repository) can be used to automate this process as well as reconfigure and restart the DNS server upon a successful run.


## Variable Substitution

In the source file variables can be declared via the following syntax:

    {{name=value}}

and substituted via:

    {{name}}

For example:

    {{ip4=192.0.2.0}}

    @   A   {{ip4}}
    www A   {{ip4}}

becomes:

    @   A   192.0.2.0
    www A   192.0.2.0

Variables are available for use at any point after their declaration.


## Include Files

Additional source files can be included via the following syntax:

    {{include:file_path:local_variable=value:...}}

The file found at `file_path` will be included in the output as though the contents of that file were included inline.
The file path is will be searched for relative to the path of the file containing the `include` command, the primary zone file, or the configured `include` directory.
Include files can include additional files.
The file path may contain standard glob patterns, all files matching the pattern will be included.
Variables defined in an include file are available for use in the file containing the `include` command at any point after the `include`.

Additional named arguments may follow the include file path,
these will define local variables available only inside the included file or files included by that file.
Local variables will override normal variables with the same name.


## Record Generation

The tool can also automatically generate the several kinds of resource records.
The format for these records is:

    {{type:arg1:arg2:arg3}}

Optional arguments my be omitted, however if all arguments are omitted, at least one colon must follow the record type to distinguish it from a variable.
Arguments may also be specified by name in order to skip optional arguments, e.g.:

    {{tlsa:443:ttl=300}}

If an argument value needs to contain a colon, equals sign, or quote, those symbols can be escaped with a backslash, e.g. `\:` or the value may be enclosed in double quotes.

Records can be disabled by prepending the record type with `-`.


### SOA Records

SOA records are specified as follows:

    {{soa:primary_server:admin:refresh:retry:expire:minimum:master_server:ttl}}

The `primary_server` and `admin` arguments are required, all others are optional.
Note that the serial number for the zone is not specified, the tool automatically generates the serial number using the format YYYYMMDD## and ensures that the generated serial number is at least one greater than the currently deployed serial number of the zone.

* `primary_server` is the name of the primary name server for the zone.
* `admin` is the email address of the zone administrator.
It may be specified in bind format or standard email format, e.g.: `admin.example.com` or `admin@example.com`.
* `refresh` is the time when the slave server(s) will refresh from the master.
The default value is `4h`.
* `retry` is retry interval for slaves to refresh from the master in case of failure.
The default value is `1h`.
* `expire` is the duration the slave will keep a zone file without a refresh from the master
The default value is `14d`.
* `minimum` is the default time the slaves should cache the zone file.
The default value is `10m`.
* `master_server` is a server to query for existing SOA serial numbers other than the `primary_server`.
The default value is the name of the primary server for the zone.
This is useful if the master server is not publicly accessible and therefore is not the same as the `primary_server`.
If the `primary_server` is not the master, be sure to set this value so that slave zone transfers happen properly after updates.
* `ttl` is the TTL value for the SOA record.
The default value is empty.

Example:

    {{soa:ns1.example.com:admin@example.com}}

Becomes:

    @   SOA ns1.example.com. admin.example.com. 2016120900 4h 1h 14d 5m


### SSHFP Records

SSHFP records are specified as follows:

    {{sshfp:hostname:key_file:ttl:type}}

All arguments are optional.

* `hostname` is the host name for the SSHFP record.
The default value is `@`.
* `key_file` is the name of the file the SSH host key files.
Key file names may be absolute or relative paths.
If the file name is an absolute path, it will be used verbatim,
otherwise the file path will be relative to the configured `ssh` directory (`/etc/ssh` by default)
and the file name will be passed into the `ssh` file name format string, adding the key type and extension.
The default value is `ssh_host`.
If using an absolute path, the `type` must also be specified.
* `ttl` is the TTL value for the SSHFP record.
The default value is empty.
* `type` is blank or one of the following: `rsa`, `dsa`, `ecdsa`, `ed25519`.
If `type` is blank, SSHFP records will be generated for all key types for which public key files can be found,
otherwise records for only the specified key type will be generated.

Two SSHFP records will be generated for each key file that is present, one with a SHA1 digest and one with a SHA256 digest.

Example:

    {{sshfp:}}

Becomes:

    @   SSHFP   1 1 8e97a98a87d8e88f17e9100ed1dc852d0b65dea7
    @   SSHFP   1 2 cae4c8dc466978685915a030cdd518df707b4aa2cdaec6bb60b5b303b9d65207
    @   SSHFP   3 1 04224f436dafa603aa7d335dd59cb03514bcb224
    @   SSHFP   3 2 44cd6dd4363ab585280904ad41013de13eaba4d35842cd2d8c25778b1defc2d9


### TLSA Records

TLSA records are specified as follows:

    {{tlsa:port:host:cert_file:usage:selector:proto:ttl:type:pass}

The `port` argument is required, all others are optional.

* `port` is the TCP port for the service.
* `host` is the host name for the service.
The default value is `@`.
* `cert_file` is the file name of the certificate or private key used to secure the service.
If the file name is an absolute path, it will be used verbatim,
otherwise the file path will be relative to the configured `certificate`, `private_key`, `backup_key`, or `previous_key` directory
and the file name will be passed into the corresponding file name format string.
Private keys will be searched for in each of the key directories.
The default value is the name of the source zone file.
* `usage` is one of the following: `pkix-ta`, `pkix-ee`, `dane-ta`, or `dane-ee`.
The default value is `pkix-ee`.
* `selector` is `cert`, or `spki`.
For `cert` selectors the `cert_file` must be a certificate, for `spki` selectors the `cert_file` may be a certificate or a private key.
The default value is `spki`.
* `proto` is one of the following: `tcp`, `udp`, `sctp`, or `dccp`.
The default value is `tcp`.
* `ttl` is the TTL value for the TLSA record.
The default value is empty.
* `type` is blank or one of the following: `rsa`, `ecdsa`.
If specified, it will restrict TLSA records to that key type,
otherwise TLSA records will be generated for all avaiable keys.
Keys will be located by appending `.rsa` and `.ecdsa` after the name of the `cert_file` (before the file extension, e.g. `example.com.ecdsa.key`).
The `.rsa` suffix is optional for RSA keys.
* `pass` is the password for encrypted private key files.
The default value is empty.

Two TLSA records will be generated for each available key type,
one using a SHA256 digest and one using a SHA512 digest.
When using the `spki` selector, the tool will additionally look for backup and previous key files.
If a backup or previous key is found, additional TLSA records will be generated for those keys.

Example:

    {{tlsa:443:www}}

Becomes:

    _443._tcp.www   TLSA    1 1 1 90cebb19a148038c14e875153311bfc27603cbc64c78c9e9432114dd76425ab4
    _443._tcp.www   TLSA    1 1 2 0f5ccb1dc77b699281c671976991acd6b597f42265329921d3273a9fcf71f599e1c6c7e15da4689a239eed9dbad0fbdfc0279ddefcf93a8f40680172ea60c4e0


### TLSA Certificate Records

TLSA Certificate records are specified as follows:

    {{tlsa_cert:port:cert_file:usage:selector:proto:ttl:type}

The `port` argument is required, all others are optional.

* `port` is the TCP port for the service.
* `cert_file` is the file name of the certificate used to secure the service.
If the file name is an absolute path, it will be used verbatim,
otherwise the file path will be relative to the configured `certificate` directory
and the file name will be passed into the corresponding file name format string.
The default value is the name of the source zone file.
* `usage` is one of the following: `pkix-ta`, `pkix-ee`, `dane-ta`, or `dane-ee`.
The default value is `pkix-ee`.
* `selector` is `cert`, or `spki`.
The default value is `spki`.
* `proto` is one of the following: `tcp`, `udp`, `sctp`, or `dccp`.
The default value is `tcp`.
* `ttl` is the TTL value for the TLSA record.
The default value is empty.
* `type` is blank or one of the following: `rsa`, `ecdsa`.
If specified, it will restrict TLSA records to that key type,
otherwise TLSA records will be generated for all avaiable keys.
Keys will be located by appending `.rsa` and `.ecdsa` after the name of the `cert_file` (before the file extension, e.g. `example.com.ecdsa.pem`).
The `.rsa` suffix is optional for RSA keys.

The host names used for the TLSA records will be taken from the subject alternative names in the certificate file.
Two TLSA records will be generated for each subject alternative name present in the certificate for each available key type,
one using a SHA256 digest and one using a SHA512 digest.
Certificates must not contain subject alternative names containing wildcards.

Example:

    {{tlsa_cert:443}}

Becomes:

    _443._tcp.www   TLSA    1 1 1 90cebb19a148038c14e875153311bfc27603cbc64c78c9e9432114dd76425ab4
    _443._tcp.www   TLSA    1 1 2 0f5ccb1dc77b699281c671976991acd6b597f42265329921d3273a9fcf71f599e1c6c7e15da4689a239eed9dbad0fbdfc0279ddefcf93a8f40680172ea60c4e0


### SMIMEA Records

SMIMEA records are specified as follows:

    {{smimea:user:host:cert_file:usage:selector:ttl:type:pass}

The `user` argument is required, all others are optional.

* `user` is the left hand side of the user's email address (before the `@`) or `*`.
* `host` is the host name for the email address.
The default value is `@`.
* `cert_file` is the file name of the certificate or private key used for S/MIME email for the user.
If the file name is an absolute path, it will be used verbatim,
otherwise the file path will be relative to the configured `certificate`, `private_key`, `backup_key`, or `previous_key` directory
and the file name will be passed into the corresponding file name format string.
Private keys will be searched for in each of the key directories.
The default value is the name of the source zone file.
By default the `user` argument + `@` will be prepended to the file name, e.g. {{smimea:user}} will search for `user@example.com.rsa.pem`, etc.
* `usage` is one of the following: `pkix-ta`, `pkix-ee`, `dane-ta`, or `dane-ee`.
The default value is `pkix-ee`.
* `selector` is `cert`, or `spki`.
For `cert` selectors the `cert_file` must be a certificate, for `spki` selectors the `cert_file` must be a private key.
The default value is `cert`.
* `ttl` is the TTL value for the SMIMEA record.
The default value is empty.
* `type` is blank or one of the following: `rsa`, `ecdsa`.
If specified, it will restrict TLSA records to that key type,
otherwise TLSA records will be generated for all avaiable keys.
Keys will be located by appending `.rsa` and `.ecdsa` after the name of the `cert_file` (before the file extension, e.g. `example.com.ecdsa.key`).
The `.rsa` suffix is optional for RSA keys.
* `pass` is the password for encrypted private key files.
The default value is empty.

Two SMIMEA records will be generated for each available key type,
one using a SHA256 digest and one using a SHA512 digest.
For `cert` selectors an additional record will be generated with the full contents of the certificate.
When using the `spki` selector, the tool will additionally look for backup and previous key files.
If a backup or previous key is found, additional SMIMEA records will be generated for those keys.

Example:

    {{smimea:username}}

Becomes:

    16f78a7d6317f102bbd95fc9a4f3ff2e3249287690b8bdad6b7810f8._smimecert SMIMEA  1 0 1 90cebb19a148038c14e875153311bfc27603cbc64c78c9e9432114dd76425ab4
    16f78a7d6317f102bbd95fc9a4f3ff2e3249287690b8bdad6b7810f8._smimecert SMIMEA  1 0 2 0f5ccb1dc77b699281c671976991acd6b597f42265329921d3273a9fcf71f599e1c6c7e15da4689a239eed9dbad0fbdfc0279ddefcf93a8f40680172ea60c4e0


### ACME Challenge Records

ACME Challenge (TXT) records are specified as follows:

    {{acme:challenge_file:ttl}}

All arguments are optional.

* `challenge_file` is the file name of the json file storing ACME challenge information.
If the file name is an absolute path, it will be used verbatim,
otherwise the file path will be relative to the configured `acme` directory
and the file name will be passed into the corresponding file name format string.
The default value is the name of the source zone file.
* `ttl` is the TTL value for the TXT record.
The default value is empty.

The contents of the ACME challenge file is a single dictionary whose keys are host names and values are the ACME challenge values.
One record will be generated for each key/value pair.
This record type is meant to be used with an automatic ACME certificate managment bot doing dns-01 authorizations,
such as [acmebot](https://github.com/plinss/acmebot).
If the challenge file does not exist, no records will be generated and no error will occour.

Example:

    {{acme:}}

Becomes:

    _acme-challenge.example.com     TXT     "Tu6B_E8PvD1aE1S4CqHPfsgkU3YcdIjhpRDFlhLu0r4"


### DKIM Records

DKIM (TXT) records are specified as follows:

    {{dkim:selector:domain:host:ttl}}

All arguments are optional.

* `selector` is the DKIM selector.
The default value is specified in the `settings` section of the config file.
* `domain` is the name of the OpenDKIM private key.
If `domain` is an absolute path, it will be used verbatim,
otherwise the file path will be relative to the configured `dkim` directory
and the file name will be passed into the corresponding file name format string.
The default value is the name of the source zone file.
* `host` is the host name for the DKIM key.
The default value is `@`
* `ttl` is the TTL value for the TXT record.
The default value is empty.

Example:

    {{dkim:}}

Becomes:

    default._domainkey  TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2G8vw5hMce1Zy2ovLnBTEbXxiOqY/CsLu+uqlyMOdOjOGtQqx1wX2aXksazjEIQ3x5RfbuvRfVn/84W4J6WI90/a606veHHalQouXLfQIlu3QuTUkjsj+aldchivc/AI/wZNiIPrPR96UGIzBbSE9zGvwpQ23Z1LzGUXAsPKx1wIDAQAB"


### DMARC Records

DMARC (TXT) records are specified as follows:

    {{dmarc:policy:rua:ruf:subdomain_policy:options:dkim_alignment:spf_alignment:report_format:interval:percent:host:ttl}}

All arguments are optional.

* `policy` is one of the following: `none`, `quarantine`, or `reject`.
The default value is `none`.
* `rua` is a comma separated lst of email addresses to receive aggregate reports.
* `ruf` is a comma separated lst of email addresses to receive forensic reports.
* `subdomain_policy` is one of the following: `none`, `quarantine`, or `reject`.
The default value is `none`.
* `options` is one of the following: `all`, `any`, `dkim`, or `spf`.
The default value is `any`.
* `dkim_alignment` is one of the following: `relaxed`, or `strict`.
The default value is `relaxed`.
* `spf_alignment` is one of the following: `relaxed`, or `strict`.
The default value is `relaxed`.
* `report_format` is one of the following: `afrf`, `iodef`.
The default value is `afrf`.
* `interval` is a numeric value (seconds).
The default values is `86400` (1 day).
* `percent` is a numeric value from 0 to 100.
The default value is `100`.
* `host` is the host name for the DKIM key.
The default value is `@`
* `ttl` is the TTL value for the TXT record.
The default value is empty.

Example:

    {{dmarc:rua@example.com:ruf@example.com}}

Becomes:

    _dmarc  TXT "v=DMARC1; rua=mailto:rua@example.com; ruf=mailto:ruf@example.com; p=none; sp=none; fo=1; adkim=r; aspf=r; rf=afrf; ri=86400; pct=100;"


### CAA Records

CAA records are specified as follows:

    {{caa:tag:caname:flag:ttl}}

The `tag` and `caname` arguments are required, all others are optional.

* `tag` is tag for the CAA record, usually `issue` or `issuewild`.
* `caname` is the name of the CA.
* `flag` is flag value for the CAA record.
The default value is `1`.
* `ttl` is the TTL value for the CAA record.
The default value is empty.

Example:

    {{caa:issue:letsencrypt.org}}

Becomes:

    @   TYPE257 \# 22 010569737375656c657473656e63727970742e6f7267


### LDAP Records

LDAP records are specified as follows:

    {{ldap:}}

Any DNS records found in the configured LDAP server matching the current zone will be included.
The following record types are supported: A, AAAA, TXT, SRV, and SSHFP.


## Sample Source Zone File

The following sample of a simple source zone file:

    {{soa:ns1.example.com:admin@example.com}}

    {{ip4=192.0.2.0}}
    {{pool6=2001:db8}}

    @   NS  ns1.example.com.
    @   NS  ns2.example.com.

    ; Mail
    @   MX  10  smtp.example.com.
    @   TXT "v=spf1 a:smtp.example.com -all"

    ; A records
    @       A       {{ip4}}
    @       AAAA    {{pool6}}::
    smtp    A       {{ip4}}
    smtp    AAAA    {{pool6}}::1
    www     A       {{ip4}}
    www     AAAA    {{pool6}}::1:0

    ; DANE records - certificate in /etc/ssl/certs/example.com.pem
    {{tlsa:25:smtp:usage=dane-ee}}
    {{tlsa:443}}
    {{tlsa:443:www}}

    ; DKIM - certificate in /etc/opendkim/keys/example.com/default.private
    {{dkim:}}
    _adsp._domainkey    TXT "dkim=all"

    ; CAA Records
    {{caa:issue:letsencrypt.org}}

    ; ACME
    {{acme:}}

Will result in the output of:

    @   SOA ns1.example.com. admin.example.com. 2016120900 4h 1h 14d 5m

    @   NS  ns1.example.com.
    @   NS  ns2.example.com.

    ; Mail
    @   MX  10  smtp.example.com.
    @   TXT "v=spf1 a:smtp.example.com -all"

    ; A records
    @       A       192.0.2.0
    @       AAAA    2001:db8::
    smtp    A       192.0.2.0
    smtp    AAAA    2001:db8::1
    www     A       192.0.2.0
    www     AAAA    2001:db8::1:0

    ; DANE records - certificate in /etc/ssl/certs/example.com.pem
    _25._tcp.smtp   TLSA    3 1 1 90cebb19a148038c14e875153311bfc27603cbc64c78c9e9432114dd76425ab4
    _25._tcp.smtp   TLSA    3 1 2 0f5ccb1dc77b699281c671976991acd6b597f42265329921d3273a9fcf71f599e1c6c7e15da4689a239eed9dbad0fbdfc0279ddefcf93a8f40680172ea60c4e0
    _443._tcp       TLSA    1 1 1 90cebb19a148038c14e875153311bfc27603cbc64c78c9e9432114dd76425ab4
    _443._tcp       TLSA    1 1 2 0f5ccb1dc77b699281c671976991acd6b597f42265329921d3273a9fcf71f599e1c6c7e15da4689a239eed9dbad0fbdfc0279ddefcf93a8f40680172ea60c4e0
    _443._tcp.www   TLSA    1 1 1 90cebb19a148038c14e875153311bfc27603cbc64c78c9e9432114dd76425ab4
    _443._tcp.www   TLSA    1 1 2 0f5ccb1dc77b699281c671976991acd6b597f42265329921d3273a9fcf71f599e1c6c7e15da4689a239eed9dbad0fbdfc0279ddefcf93a8f40680172ea60c4e0

    ; DKIM - certificate in /etc/opendkim/keys/example.com/default.private
    default._domainkey  TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2G8vw5hMce1Zy2ovLnBTEbXxiOqY/CsLu+uqlyMOdOjOGtQqx1wX2aXksazjEIQ3x5RfbuvRfVn/84W4J6WI90/a606veHHalQouXLfQIlu3QuTUkjsj+aldchivc/AI/wZNiIPrPR96UGIzBbSE9zGvwpQ23Z1LzGUXAsPKx1wIDAQAB"
    _adsp._domainkey    TXT "dkim=all"

    ; CAA Records
    @   TYPE257 \# 22 010569737375656c657473656e63727970742e6f7267

    ; ACME


#!/usr/bin/env python3

# This tool does variable substitution and generates special Resource Records
#
# To install on Debian:
# sudo pip3 install -r requirements.txt
#
# To define a variable: {{varname=value}}
# To use a variable: {{varname}}
# To create a special Resource Record: {{type:param1:param2:...}}
#   optional params may be identified by keyword, e.g.: {{type:param1:param4name=value}}
#
# Special Resource Records available are:
#   {{soa:primary_server:admin[:refresh:retry:expire:minimum:master_server:ttl]}}
#       defaults are: refresh=4h, retry=1h, expire=14d, minimum=10m
#   {{sshfp:[hostname:key_file:ttl:type]}}
#       key_file defaults to 'ssh_host', if not abs path, looks in /etc/ssh
#       key_file must not include _<type>_key.pub
#   {{tlsa:port[:host:cert_file:usage:selector:proto:ttl:type:pass]}
#       if cert_file not abs path, looks in /etc/ssl/certs
#       proto defaults to tcp
#       usage one of pkix-ta, pkix-ee, dane-ta, dane-ee - defaults to pkix-ee
#       selector one of cert, spki - defaults to spki
#   {{tlsa_cert:port[:cert_file:usage:selector:proto:ttl:type]}
#       if cert_file not abs path, looks in /etc/ssl/certs
#       proto defaults to tcp
#       usage one of pkix-ta, pkix-ee, dane-ta, dane-ee - defaults to pkix-ee
#       selector one of cert, spki - defaults to spki
#   {{smimea:user[:host:cert_file:usage:selector:ttl:type:pass}}
#       if cert_file not abs path, looks in /etc/ssl/certs
#       usage one of pkix-ta, pkix-ee, dane-ta, dane-ee - defaults to pkix-ee
#       selector one of cert, spki - defaults to cert
#   {{acme:[challenge_file:ttl]}}
#       if challenge_file not abs path, looks in /etc/ssl/challenges
#   {{dkim:[selector:domain:host:ttl]}}
#   {{dmarc:[policy:rua:ruf:subdomain_policy:options:dkim_alignment:spf_alignment:report_format:interval:percent:ttl]}}
#       policy defaults to none, one of none, quarantine, reject
#       rua email adresses to send aggregate reports (comma separated)
#       ruf email adresses to send forensic reports (comma separated)
#       subdomain_policy one of none, quarantine, reject
#       options one of all, any, dkim, spf
#       dkim_alignment one of strict or relaxed
#       spf_alignment one of strict or relaxed
#       report_format one of afrf or iodef
#       interval number of seconds
#       percent percent of messages to apply
#   {{pgp:key_file[:ttl]}}
#   {{caa:tag:caname[:host:flag:ttl]}}
#   {{include:file_path}}


import argparse
import base64
import binascii
import collections
import datetime
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import unicodedata
from collections import abc
from importlib import metadata

import DNS

import ldap


class BindToolError(Exception):
    """General error."""

    pass


class BindTool:
    """Bind9 zone file processor."""

    def __init__(self):
        script_entry = sys.argv[0]
        self.script_dir = os.path.dirname(os.path.realpath(script_entry))
        self.script_name = os.path.basename(script_entry)

        argparser = argparse.ArgumentParser(description='Preprocess bind zone files')
        argparser.add_argument('--version', action='version', version='%(prog)s ' + metadata.version('bindtool'))
        argparser.add_argument('zone_file_path')
        argparser.add_argument('out_file_path', nargs='?')
        argparser.add_argument('-d', '--debug',
                               action='store_true', dest='debug', default=False,
                               help='print detailed debugging information to stdout')
        argparser.add_argument('-c', '--config',
                               dest='config_path', default=f'{self.script_name}.json', metavar='CONFIG_PATH',
                               help='Specify file path for config')
        self.args = argparser.parse_args()
        if (not self.args.zone_file_path):
            argparser.print_usage()

        if (self.args.debug):
            sys.excepthook = debug_hook

        zone_name = os.path.basename(self.args.zone_file_path)
        self.config, self.config_dir = self._load_config(self.args.config_path, ('.', os.path.join('/etc', self.script_name), self.script_dir), zone_name)
        self._config_defaults = {
            'defaults': {
                'soa': {
                    'refresh': '4h',
                    'retry': '1h',
                    'expire': '14d',
                    'minimum': '10m',
                    'master_server': None,
                    'ttl': None,
                },
                'sshfp': {
                    'host': '@',
                    'key_file': 'ssh_host',
                    'ttl': None,
                    'type': None,
                },
                'tlsa': {
                    'port': 443,
                    'host': None,
                    'usage': 'pkix-ee',
                    'selector': 'spki',
                    'proto': 'tcp',
                    'ttl': None,
                    'type': None,
                    'pass': None,
                },
                'tlsa_cert': {
                    'port': 443,
                    'usage': 'pkix-ee',
                    'selector': 'spki',
                    'proto': 'tcp',
                    'ttl': None,
                    'type': None,
                    'pass': None,
                },
                'smimea': {
                    'host': None,
                    'usage': 'pkix-ee',
                    'selector': 'cert',
                    'ttl': None,
                    'type': None,
                    'pass': None,
                },
                'acme': {
                    'ttl': 60,
                },
                'caa': {
                    'host': '@',
                    'flag': 0,
                    'ttl': None,
                },
                'dkim': {
                    'host': None,
                    'ttl': None,
                    'selector': 'default',
                },
                'dmarc': {
                    'policy': 'none',
                    'rua': None,
                    'ruf': None,
                    'subdomain_policy': 'none',
                    'options': 'any',
                    'dkim_alignment': 'relaxed',
                    'spf_alignment': 'relaxed',
                    'report_format': 'afrf',
                    'interval': 86400,
                    'percent': 100,
                    'ttl': None,
                },
                'include': {
                    'file': None,
                }
            },
            'ldap': {
                'url': '',
                'user_dn': '',
                'password': '',
                'search_base': '',
                'filter': '(objectClass=dNSZone)',
            },
            'directories': {
                'certificate': '/etc/ssl/certs',
                'private_key': '/etc/ssl/private',
                'backup_key': '/etc/ssl/private',
                'previous_key': '/etc/ssl/previous',
                'dkim': '/etc/opendkim/keys/{domain}',
                'ssh': '/etc/ssh',
                'acme': '/etc/ssl/challenges',
                'include': '/etc/bind/includes',
                'cache': '/var/local/bindtool',
            },
            'key_type_suffixes': {
                'rsa': '.rsa',
                'ecdsa': '.ecdsa',
            },
            'file_names': {
                'certificate': '{username}{name}{suffix}.pem',
                'private_key': '{username}{name}{suffix}.key',
                'backup_key': '{username}{name}_backup{suffix}.key',
                'previous_key': '{username}{name}_previous{suffix}.key',
                'dkim': '{selector}.private',
                'ssh': '{name}_{key_type}_key.pub',
                'acme': '{name}',
                'include': '{name}',
                'zone_file': '{name}',
                'include_parent': '{name}',
                'cache': '{name}.ldap',
            },
        }
        self._cert_suffixes = {
            '': ('', '.rsa', '.ecdsa'),
            'rsa': ('', '.rsa'),
            'ecdsa': ('.ecdsa')
        }
        self._key_suffixes = {
            '': ('', '.rsa', '.ecdsa', '_backup', '_backup.rsa', '_backup.ecdsa', '_previous', '_previous.rsa', '_previous.ecdsa'),
            'rsa': ('', '.rsa', '_backup', '_backup.rsa', '_previous', '_previous.rsa'),
            'ecdsa': ('.ecdsa', '_backup.ecdsa', '_previous.ecdsa')
        }

        self.certificates = {}
        self.public_keys = {}

    def _zone_config_file_path(self, config_file_path, zone_name):
        config_dir, config_filename = os.path.split(config_file_path)
        if ('.' in config_filename):
            name, extension = config_filename.rsplit('.', 1)
            return os.path.join(config_dir, f'{name}.{zone_name}.{extension}')
        return os.path.join(config_dir, f'{name}.{zone_name}')

    def _merge_config(self, base, extra):
        if (base is None):
            base = collections.OrderedDict()
        for name, value in extra.items():
            if (isinstance(value, abc.Mapping)):
                base[name] = self._merge_config(base.get(name), value)
            else:
                base[name] = value
        return base

    def _load_config_file(self, config_file_path):
        if (os.path.isfile(config_file_path)):
            try:
                with open(config_file_path) as config_file:
                    return json.load(config_file, object_pairs_hook=collections.OrderedDict)
            except Exception as error:
                self._error('Error reading config file ', config_file_path, ': ', error, '\n')
        return {}

    def _load_config(self, file_path, search_paths, zone_name):
        search_paths = [''] if (os.path.isabs(file_path)) else search_paths
        for search_path in reversed(search_paths):
            config_file_path = os.path.join(search_path, file_path)
            zone_config_file_path = self._zone_config_file_path(config_file_path, zone_name)
            if (os.path.isfile(config_file_path) or os.path.isfile(zone_config_file_path)):
                config = None
                config = self._merge_config(config, self._load_config_file(config_file_path))
                config = self._merge_config(config, self._load_config_file(zone_config_file_path))
                return (config, os.path.dirname(os.path.abspath(config_file_path)))
        return (config, '')

    def _message(self, *args):
        message = ''
        for arg in args:
            message += str(arg, 'utf-8', 'replace') if isinstance(arg, bytes) else str(arg)
        return message

    def _debug(self, *args):
        if (self.args.debug):
            sys.stdout.write(self._message(*args))

    def _warn(self, *args):
        sys.stderr.write('WARNING: ' + self._message(*args))

    def _error(self, *args):
        message = self._message(*args)
        sys.stderr.write('ERROR: ' + message)
        raise BindToolError(message)

    def _config(self, section_name, key=None, default=None):
        return self.config.get(section_name, {}).get(key, default) if (key) else self.config.get(section_name, {})

    def _defaults(self, type, fill={}):
        out = fill
        defaults = self._config('defaults', type, {})
        for key, value in defaults.items():
            out[key] = str(value) if (value is not None) else ''
        return out

    def _ldap(self, key):
        return self._config('ldap', key)

    def _directory(self, file_type):
        directory = self._config('directories', file_type, '')
        return os.path.normpath(os.path.join(self.config_dir, directory)) if (directory) else directory

    def _key_type_suffix(self, key_type):
        return self._config('key_type_suffixes', key_type, '')

    def _file_name(self, file_type):
        return self._config('file_names', file_type, '')

    def _file_path(self, file_type, file_name, key_type=None, replace_wildcard=True, **kwargs):
        if (os.path.isabs(file_name)):
            return file_name
        if (self._directory(file_type) is not None):
            directory = self._directory(file_type).format(name=file_name, key_type=key_type, suffix=self._key_type_suffix(key_type), **kwargs)
            file_name = self._file_name(file_type).format(name=file_name, key_type=key_type, suffix=self._key_type_suffix(key_type), **kwargs)
            return os.path.join(directory, file_name.replace('*', '_') if (replace_wildcard) else file_name)
        return ''

    def _find_file(self, file_types, file_name, key_type=None, **kwargs):
        if (isinstance(file_types, str)):
            file_types = [file_types]
        for file_type in file_types:
            if (file_type):
                file_path = os.path.expanduser(self._file_path(file_type, file_name, key_type, **kwargs))
                if (os.path.isfile(file_path)):
                    return file_path
        return None

    def _find_files(self, file_types, file_name, key_type=None, **kwargs):
        result = []
        if (isinstance(file_types, str)):
            file_types = [file_types]
        for file_type in file_types:
            if (file_type):
                file_paths = glob.glob(os.path.expanduser(self._file_path(file_type, file_name, key_type, replace_wildcard=False, **kwargs)))
                for file_path in sorted(file_paths):
                    if (os.path.isfile(file_path) and (file_path not in result)):
                        result.append(file_path)
        return result

    def _makedir(self, dir_path, chmod=None, warn=True):
        if (not os.path.isdir(dir_path)):
            try:
                os.makedirs(dir_path)
                if (chmod):
                    if (chmod & 0o700):
                        chmod |= 0o100
                    if (chmod & 0o070):
                        chmod |= 0o010
                    if (chmod & 0o007):
                        chmod |= 0o001
                    try:
                        os.chmod(dir_path, chmod)
                    except PermissionError as error:
                        if (warn):
                            self._warn('Unable to set directory mode for ', dir_path, '\n', self._indent(error), '\n')
            except Exception as error:
                if (warn):
                    self._warn('Unable to create directory ', dir_path, '\n', self._indent(error), '\n')

    def _open_file(self, file_path, mode='r', chmod=0o666, warn=True):
        def opener(file_path, flags):
            return os.open(file_path, flags, mode=chmod)
        if ((('w' in mode) or ('a' in mode)) and isinstance(file_path, str)):
            self._makedir(os.path.dirname(file_path), chmod=chmod, warn=warn)
        return open(file_path, mode, opener=opener)

    def _copy_defaults(self, source, target):
        for key, value in source.items():
            if (key not in target):
                target[key] = source[key]
            else:
                if (isinstance(source[key], dict) and isinstance(target[key], collections.OrderedDict)):
                    self._copy_defaults(source[key], target[key])

    def _validate_config(self, zone_file_path):
        if ('directories' not in self.config):
            self.config['directories'] = collections.OrderedDict()
        for legacy_directory in ['certificate_path', 'private_key_path', 'backup_key_path', 'previous_key_path',
                                 'dkim_path', 'ssh_path', 'acme_path', 'include_path']:
            if (legacy_directory in self.config):
                self.config['directories'][legacy_directory[:-5]] = self.config[legacy_directory]
                del self.config[legacy_directory]
        self._copy_defaults(self._config_defaults, self.config)
        self.config['directories']['zone_file'] = os.path.dirname(os.path.realpath(zone_file_path))

    def _split_command(self, command):
        parts = []
        name = ''
        value = ''
        count = len(command)
        index = 0
        while (index < count):
            if ('"' == command[index]):
                index += 1
                while (index < count):
                    if ('"' == command[index]):
                        break
                    value += command[index]
                    index += 1
            elif ('\\' == command[index]):
                index += 1
                if (index < count):
                    value += command[index]
            elif ('=' == command[index]):
                name = value
                value = ''
            elif (':' == command[index]):
                parts.append((name.strip(), value.strip()))
                name = ''
                value = ''
            else:
                value += command[index]
            index += 1
        parts.append((name.strip(), value.strip()))
        return (parts[0][1], parts[1:])

    def _parse_params(self, type, params, names, defaults, prefixes, command):
        out = self._defaults(type, defaults)
        while (0 < len(params)):
            name, value = params.pop(0)
            if (name):
                if (name in names):
                    names.remove(name)
            else:
                if (0 < len(names)):
                    name = names.pop(0)
                else:
                    self._error('Non-positional record arguments must have names {{', command, '}}\n')
            if (value or (name not in out)):
                out[name] = value
        for name in prefixes:
            if ((name in out) and out[name]):
                out[name] = prefixes[name] + out[name]
        return out

    def _wrap(self, value, length=80, threshold=100):
        if (len(value) <= threshold):
            return value
        output = '(\n'
        while (0 < len(value)):
            output += '\t\t' + value[0:length] + '\n'
            value = value[length:]
        output += '\t)'
        return output

    def _generic_rr(self, params, type, value):
        return '{host}{ttl}\tTYPE{type}\t\\# {len} {data}\n'.format(type=type, len=len(value), data=self._wrap(self._hex(value)), **params)

    def _txt_rr(self, params, host, data, length=80, threshold=100):
        params['host'] = host
        output = '{host}{ttl}\tTXT\t'.format(**params)
        if (len(data) <= min(255, threshold)):
            return output + '"' + data + '"\n'
        length = min(255, length)
        output += '(\n'
        while (0 < len(data)):
            output += '\t\t"' + data[:length] + '"\n'
            data = data[length:]
        output += '\t)\n'
        return output

    def _hex(self, value):
        return binascii.hexlify(value).decode('ascii')

    def _sha1(self, value):
        return hashlib.sha1(value).hexdigest()

    def _sha256(self, value):
        return hashlib.sha256(value).hexdigest()

    def _sha512(self, value):
        return hashlib.sha512(value).hexdigest()

    def _load_certificates(self, cert_file_name, type, username=''):
        certificates = []
        username = (username + '@') if (username) else username
        key_types = [type] if (type) else ['rsa', 'ecdsa']

        for key_type in key_types:
            cert_file_path = self._find_file('certificate', cert_file_name, key_type=key_type, username=username)
            if (cert_file_path):
                if (cert_file_path in self.certificates):
                    certificates.append(self.certificates[cert_file_path])
                else:
                    self._debug('Loading certificate ', cert_file_path, '\n')
                    certificate = subprocess.check_output(['openssl', 'x509', '-in', cert_file_path, '-outform', 'DER'])
                    self.certificates[cert_file_path] = certificate
                    certificates.append(certificate)
        if (not certificates):
            self._warn('Certificate file ', cert_file_name, ' not found\n')
        return certificates

    def _extract_public_key(self, public_key_pem):
        if (public_key_pem):
            match = re.match(r'-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----', public_key_pem.decode('ascii'), re.DOTALL)
            if (match):
                return base64.b64decode(match.group(1))
        return None

    def _public_key_from_certificate(self, cert_file_path):
        return self._extract_public_key(subprocess.check_output(['openssl', 'x509', '-in', cert_file_path, '-pubkey', '-noout']))

    def _public_key_from_private_key(self, private_key_path, passphrase):
        pass_arg = ['-passin', 'pass:{passphrase}'.format(passphrase=passphrase)] if (passphrase) else []
        try:
            return self._extract_public_key(subprocess.check_output(['openssl', 'rsa', '-in', private_key_path, '-pubout'] + pass_arg,
                                                                    stderr=subprocess.DEVNULL))
        except:
            return self._extract_public_key(subprocess.check_output(['openssl', 'ec', '-in', private_key_path, '-pubout'] + pass_arg,
                                                                    stderr=subprocess.DEVNULL))

    def _load_public_keys(self, cert_file_name, type, passphrase, username=''):
        public_keys = []
        username = (username + '@') if (username) else username
        key_types = [type] if (type) else ['rsa', 'ecdsa']

        for key_type in key_types:
            cert_file_path = self._find_file('certificate', cert_file_name, key_type=key_type, username=username)
            if (cert_file_path):
                if (cert_file_path in self.public_keys):
                    public_keys.append(self.public_keys[cert_file_path])
                else:
                    self._debug('Loading public key from certificate ', cert_file_path, '\n')
                    public_key = self._public_key_from_certificate(cert_file_path)
                    self.public_keys[cert_file_path] = public_key
                    public_keys.append(public_key)
            else:
                private_key_path = self._find_file(['private_key', 'backup_key', 'previous_key'],
                                                   cert_file_name, key_type=key_type, username=username)
                if (private_key_path):
                    if (private_key_path in self.public_keys):
                        public_keys.append(self.public_keys[private_key_path])
                    else:
                        self._debug('Loading public key from private key ', private_key_path, '\n')
                        public_key = self._public_key_from_private_key(private_key_path, passphrase)
                        self.public_keys[cert_file_path] = public_key
                        public_keys.append(public_key)
        if (not public_keys):
            self._warn('Certificate or private key file not found for ', cert_file_name, '\n')
        return public_keys

    def _alternative_names_from_certificate(self, cert_file_name, type):
        alternative_names = set()
        key_types = [type] if (type) else ['rsa', 'ecdsa']
        regex = re.compile('.*X509v3 Subject Alternative Name:\\s*([^\\n]*)\\n.*', re.DOTALL)

        for key_type in key_types:
            cert_file_path = self._find_file('certificate', cert_file_name, key_type=key_type, username='')
            if (cert_file_path):
                self._debug('Loading alternative names from certificate ', cert_file_path, '\n')
                match = regex.match(subprocess.check_output(['openssl', 'x509', '-in', cert_file_path, '-noout', '-text']).decode('ascii'))
                if (match):
                    alternative_names |= set([name[4:] for name in match.group(1).split(', ') if name.startswith('DNS:')])
        return alternative_names

    def _load_dkim_public_key(self, selector, domain):
        key_file_path = self._find_file('dkim', domain, selector=selector, domain=domain)
        if (key_file_path):
            return subprocess.check_output(['openssl', 'rsa', '-in', key_file_path, '-outform', 'DER', '-pubout'], stderr=subprocess.DEVNULL)
        self._warn('DKIM key ', selector, ' for ', domain, ' not found\n')

    def _validate(self, params, command, param, values, convert=None):
        if (params[param] not in values):
            self._error('Unknown value "', params[param], '" for ', param, ' in {{', command, '}}\n',
                        'Must be one of: "', '", "'.join(values), '"\n')
        if (convert):
            params[param] = convert[values.index(params[param])]

    def _validate_numeric(self, params, command, param):
        if (not params[param].isdigit()):
            self._error(param.title(), ' must be numeric for {{', command, '}}\n')

    def soa_record(self, params, command, zone_name):
        params = self._parse_params('soa', params, ['primary_server', 'admin', 'refresh', 'retry', 'expire', 'minimum', 'master_server', 'ttl'],
                                    {}, {'ttl': '\t'}, command)
        if ('primary_server' not in params):
            self._error('soa record must specify primary server {{', command, '}}\n')
        if ('admin' not in params):
            self._error('soa record must specify admin {{', command, '}}\n')
        if (not params['primary_server'].endswith('.')):
            params['primary_server'] += '.'
        params['admin'] = params['admin'].replace('@', '.')
        if (not params['admin'].endswith('.')):
            params['admin'] += '.'

        master_server = params['master_server'] if (params['master_server']) else params['primary_server']
        try:
            response = DNS.Request().req(server=master_server, name=zone_name, qtype='SOA')
            existing_serial = response.answers[0]['data'][2][1] if (response and ('NOERROR' == response.header['status'])) else 0
            self._debug('Found serial number ', existing_serial, '\n')
        except Exception as error:
            self._error('Unable to perform DNS SOA query\n', error, '\n')
        serial = max(int(datetime.datetime.now().strftime('%Y%m%d00')), existing_serial + 1)
        self._debug('Using serial number ', serial, '\n')

        return '@{ttl}\tSOA\t{primary_server} {admin} {serial} {refresh} {retry} {expire} {minimum}\n'.format(serial=serial, **params)

    def sshfp_record(self, params, command, zone_name):
        params = self._parse_params('sshfp', params, ['host', 'key_file', 'ttl', 'type'], {}, {'ttl': '\t'}, command)
        self._validate(params, command, 'type', ('', 'rsa', 'dsa', 'ecdsa', 'ed25519'))

        key_type_value = {'rsa': 1, 'dsa': 2, 'ecdsa': 3, 'ed25519': 4}
        key_types = [params['type']] if (params['type']) else ['rsa', 'dsa', 'ecdsa', 'ed25519']

        found = False
        output = ''
        for key_type in key_types:
            key_file_path = self._find_file('ssh', params['key_file'], key_type=key_type)
            if (key_file_path):
                found = True
                try:
                    with open(key_file_path) as keyFile:
                        key_text = keyFile.read().split(' ')
                        key = base64.b64decode(key_text[1])

                        output += '{host}{ttl}\tSSHFP\t{key_type} 1 {digest}\n'.format(key_type=key_type_value[key_type], digest=self._sha1(key), **params)
                        output += '{host}{ttl}\tSSHFP\t{key_type} 2 {digest}\n'.format(key_type=key_type_value[key_type], digest=self._sha256(key), **params)
                except Exception as error:
                    self._error('Unable to read key from ', key_file_path, '\n', error, '\n')
        if (not found):
            self._warn('No SSH keys found for: ', params['host'], ' matching: ', params['key_file'], '\n')
        return output

    def tlsa_record(self, params, command, zone_name):
        params = self._parse_params('tlsa', params, ['port', 'host', 'cert_file', 'usage', 'selector', 'proto', 'ttl', 'type', 'pass'],
                                    {'cert_file': zone_name}, {'host': '.', 'ttl': '\t'}, command)
        self._validate_numeric(params, command, 'port')
        self._validate(params, command, 'usage', ('pkix-ta', 'pkix-ee', 'dane-ta', 'dane-ee'), ('0', '1', '2', '3'))
        self._validate(params, command, 'selector', ('cert', 'spki'), ('0', '1'))
        self._validate(params, command, 'proto', ('tcp', 'udp', 'sctp', 'dccp'))
        self._validate(params, command, 'type', ('', 'rsa', 'ecdsa'))

        if ('cert' == params['selector']):
            payloads = self._load_certificates(params['cert_file'], params['type'])
        else:
            payloads = self._load_public_keys(params['cert_file'], params['type'], params['pass'])
        if (not payloads):
            return ''

        record = '_{port}._{proto}{host}{ttl}\tTLSA\t{usage} {selector} '.format(**params)
        output = ''
        for payload in payloads:
            output += record + '1 {digest}\n'.format(digest=self._sha256(payload))
            output += record + '2 {digest}\n'.format(digest=self._sha512(payload))
        return output

    def tlsa_cert_record(self, params, command, zone_name):
        params = self._parse_params('tlsa_cert', params, ['port', 'cert_file', 'usage', 'selector', 'proto', 'ttl', 'type'],
                                    {'cert_file': zone_name}, {'ttl': '\t'}, command)
        self._validate_numeric(params, command, 'port')
        self._validate(params, command, 'usage', ('pkix-ta', 'pkix-ee', 'dane-ta', 'dane-ee'), ('0', '1', '2', '3'))
        self._validate(params, command, 'selector', ('cert', 'spki'), ('0', '1'))
        self._validate(params, command, 'proto', ('tcp', 'udp', 'sctp', 'dccp'))
        self._validate(params, command, 'type', ('', 'rsa', 'ecdsa'))

        alternative_names = self._alternative_names_from_certificate(params['cert_file'], params['type'])
        if (not alternative_names):
            return ''

        if ('cert' == params['selector']):
            payloads = self._load_certificates(params['cert_file'], params['type'])
        else:
            payloads = self._load_public_keys(params['cert_file'], params['type'], params['pass'])
        if (not payloads):
            return ''

        output = ''
        for host in alternative_names:
            if ('*' in host):
                self._error('tlsa_cert record certificate ', params['cert_file'], ' must not include wildcard hosts\n')
            record = '_{port}._{proto}.{host}{ttl}\tTLSA\t{usage} {selector} '.format(host=host, **params)
            for payload in payloads:
                output += record + '1 {digest}\n'.format(digest=self._sha256(payload))
                output += record + '2 {digest}\n'.format(digest=self._sha512(payload))
        return output

    def _email_hash(self, localpart):
        if ('*' != localpart):
            localpart = unicodedata.normalize('NFC', localpart)
            return self._sha256(localpart.encode('utf-8'))[:56]
        return localpart

    def smimea_record(self, params, command, zone_name):
        params = self._parse_params('smimea', params, ['user', 'host', 'cert_file', 'usage', 'selector', 'ttl', 'type', 'pass'],
                                    {'cert_file': zone_name}, {'host': '.', 'ttl': '\t'}, command)
        if ('user' not in params):
            self._error('smimea record must specify user {{', command, '}}\n')
        self._validate(params, command, 'usage', ('pkix-ta', 'pkix-ee', 'dane-ta', 'dane-ee'), ('0', '1', '2', '3'))
        self._validate(params, command, 'selector', ('cert', 'spki'), ('0', '1'))
        self._validate(params, command, 'type', ('', 'rsa', 'ecdsa'))

        userhash = self._email_hash(params['user'])

        if ('cert' == params['selector']):
            payloads = self._load_certificates(params['cert_file'], params['type'], params['user'])
        else:
            payloads = self._load_public_keys(params['cert_file'], params['type'], params['pass'], params['user'])
        if (not payloads):
            return ''

        record = '{userhash}._smimecert{host}{ttl}\tSMIMEA\t{usage} {selector} '.format(userhash=userhash, **params)
        output = ''
        for payload in payloads:
            output += record + '0 {cert}\n'.format(cert=self._wrap(self._hex(payload), 120, 125)) if ('cert' == params['selector']) else ''
            output += record + '1 {digest}\n'.format(digest=self._sha256(payload))
            output += record + '2 {digest}\n'.format(digest=self._sha512(payload))
        return output

    def acme_record(self, params, command, zone_name):
        params = self._parse_params('acme', params, ['challenge_file', 'ttl'], {'challenge_file': zone_name}, {'ttl': '\t'}, command)

        output = ''
        challenge_path = self._find_file('acme', params['challenge_file'])
        if (challenge_path):
            with open(challenge_path) as challenge_file:
                challenges = json.load(challenge_file, object_pairs_hook=collections.OrderedDict)
            for host in challenges:
                output += self._txt_rr(params, '_acme-challenge.' + (host[2:] if (host.startswith('*.')) else host) + '.', challenges[host])
        else:
            self._debug('ACME challenge file ', params['challenge_file'], ' not found\n')
        return output

    def _caa_rr(self, params, flag, tag, caname):
        return self._generic_rr(params, 257,
                                int(flag).to_bytes(1, byteorder='big') + len(tag).to_bytes(1, byteorder='big')
                                + tag.encode('ascii') + caname.encode('ascii'))

    def caa_record(self, params, command, zone_name):
        params = self._parse_params('caa', params, ['tag', 'caname', 'host', 'flag', 'ttl'],
                                    {}, {'ttl': '\t'}, command)
        if ('tag' not in params):
            self._error('caa record must specify tag {{', command, '}}\n')
        if ('caname' not in params):
            self._error('caa record must specify caname {{', command, '}}\n')
        self._validate_numeric(params, command, 'flag')

        return self._caa_rr(params, params['flag'], params['tag'], params['caname'])

    def dkim_record(self, params, command, zone_name):
        params = self._parse_params('dkim', params, ['selector', 'domain', 'host', 'ttl'],
                                    {'domain': zone_name}, {'host': '.', 'ttl': '\t'}, command)

        dkim_public_key = self._load_dkim_public_key(params['selector'], params['domain'])
        if (dkim_public_key):
            return self._txt_rr(params, '{selector}._domainkey{host}'.format(**params),
                                'v=DKIM1; k=rsa; p={key}'.format(key=base64.b64encode(dkim_public_key).decode('ascii')))
        return ''

    def dmarc_record(self, params, command, zone_name):
        params = self._parse_params('dmarc', params, ['policy', 'rua', 'ruf', 'subdomain_policy', 'options', 'dkim_alignment', 'spf_alignment',
                                                      'report_format', 'interval', 'percent', 'ttl'],
                                    {}, {'ttl': '\t'}, command)

        if (params['rua']):
            params['rua'] = 'rua=' + ','.join([('mailto:' + addr.strip()) for addr in params['rua'].split(',')]) + '; '
        if (params['ruf']):
            params['ruf'] = 'ruf=' + ','.join([('mailto:' + addr.strip()) for addr in params['ruf'].split(',')]) + '; '

        self._validate(params, command, 'policy', ('none', 'quarantine', 'reject'))
        self._validate(params, command, 'subdomain_policy', ('none', 'quarantine', 'reject'))
        self._validate(params, command, 'options', ('all', 'any', 'dkim', 'spf'), ('0', '1', 'd', 's'))
        self._validate(params, command, 'dkim_alignment', ('strict', 'relaxed'), ('s', 'r'))
        self._validate(params, command, 'spf_alignment', ('strict', 'relaxed'), ('s', 'r'))
        self._validate(params, command, 'report_format', ('afrf', 'iodef'))
        self._validate_numeric(params, command, 'interval')
        self._validate_numeric(params, command, 'percent')

        return self._txt_rr(params, '_dmarc',
                            'v=DMARC1; p={policy}; {rua}{ruf}sp={subdomain_policy}; fo={options}; adkim={dkim_alignment}; aspf={spf_alignment}; '
                            'rf={report_format}; ri={interval}; pct={percent};'.format(**params))

    def pgp_record(self, params, command, zone_name):
        self._error('pgp records not yet supported\n')

    def _decode_zone(self, zone):
        return {key: [value.decode('ascii') for value in values] for key, values in zone[1].items()}

    def _load_ldap_zones(self, zone_name):
        zones = {}
        cache_file_path = self._file_path('cache', zone_name)
        if (os.path.isfile(cache_file_path)):
            try:
                with open(cache_file_path) as cache_file:
                    zones = json.load(cache_file)
            except Exception as error:
                self._error('Error reading cache file ', cache_file_path, ': ', error, '\n')

        if (not self._ldap('url')):
            self._error('No LDAP server configured\n')

        ldap_server = ldap.initialize(self._ldap('url'))
        try:
            ldap_server.bind_s(self._ldap('user_dn'), self._ldap('password'), ldap.AUTH_SIMPLE)
        except Exception as error:
            self._warn('Unable to bind to LDAP server: ', error, '\n')
            return zones

        try:
            zones = ldap_server.search_s('zoneName={zone_name}.,{base}'.format(zone_name=zone_name, base=self._ldap('search_base')),
                                         ldap.SCOPE_SUBTREE, filterstr=self._ldap('filter'))
            zones = [self._decode_zone(zone) for zone in zones]
            try:
                with self._open_file(cache_file_path, mode='w', chmod=0o600) as cache_file:
                    json.dump(zones, cache_file)
            except Exception as error:
                self._error('Unable to save ldap cache: ', error, '\n')

        except:
            pass
        return zones

    def ldap_record(self, params, command, zone_name):
        zones = self._load_ldap_zones(zone_name)
        output = ''
        record_type_map = {
            'aRecord': 'A',
            'aAAARecord': 'AAAA',
            'tXTRecord': 'TXT',
            'sRVRecord': 'SRV',
            'sSHFPRecord': 'SSHFP',
            'mXRecord': 'MX',
            'cNAMERecord': 'CNAME',
            'dNameRecord': 'DNAME',
            'LocRecord': 'LOC',
            'pTRRecord': 'PTR',
            'nAPTRRecord': 'NAPTR',
            'certRecord': 'CERT',
            'dSRecord': 'DS',
            'aFSDBRecord': 'AFSDB',
        }
        def _record(record_type, host, data):
            if ('TXT' == record_type):
                return self._txt_rr({'ttl': ''}, host, data)
            data = data.replace(';', r'\;')
            return f"{host}\t{record_type}\t{data}\n"

        for zone in zones:
            if (zone['zoneName'][0] == (zone_name + '.')):
                for record_type in record_type_map:
                    if (record_type in zone):
                        for record in zone[record_type]:
                            output += _record(record_type_map[record_type], zone['relativeDomainName'][0], record)
        return output

    def include(self, params, command, zone_name, zone_file_path, param_vars):
        params = self._parse_params('include', params, ['file'], {}, {}, command)
        if (not params['file']):
            self._error('Include file path not specified\n')
        hold_include_parent = self.config['directories'].get('include_parent')
        self.config['directories']['include_parent'] = os.path.dirname(os.path.realpath(zone_file_path))
        include_file_paths = self._find_files(['include_parent', 'zone_file', 'include'], params['file'])
        self.config['directories']['include_parent'] = hold_include_parent
        if ((not include_file_paths) and ('*' not in params['file']) and ('?' not in params['file'])):
            self._error('Include file "', params['file'], '" not found\n')
        del params['file']
        local_vars = {}
        for key, value in param_vars.items():
            local_vars[key] = value
        for key, value in params.items():
            local_vars[key] = value

        output = ''
        has_soa = False
        for include_file_path in include_file_paths:
            file_output, file_has_soa = self._process_zone_file(include_file_path, zone_name, local_vars)
            output += file_output
            has_soa = has_soa or file_has_soa
        return output, has_soa

    def _append(self, output, records):
        last_line_index = output.rfind('\n')
        if (-1 < last_line_index):
            last_line = output[last_line_index + 1:]
            if (';' in last_line):
                return output + '\n;'.join([record for record in records.split('\n')])
        return output + records

    def _process_zone_file(self, zone_file_path, zone_name, param_vars):
        if (not os.path.isfile(zone_file_path)):
            self._error('Zone file ', zone_file_path, ' not found\n')

        with open(zone_file_path, 'r') as zone_file:
            input = zone_file.read()
            output = ''
            template_regex = re.compile(r'(.*?)(?:\{\{|\[\[)(.*?)(?:\}\}|\]\])(.*)', re.DOTALL)
            has_soa = False
            while (input and (0 < len(input))):
                match = template_regex.match(input)
                if (match):
                    output += match.group(1)
                    command = match.group(2)
                    input = match.group(3)
                    self._debug('processing ', command, '\n')
                    if (command.startswith('-')):
                        pass
                    elif (re.match(r'^[a-z_]+:', command)):
                        if (((0 == len(output)) or ('\n' == output[-1])) and ('\n' == input[0:1])):
                            input = input[1:]
                        record, params = self._split_command(command)
                        if ('soa' == record):
                            output = self._append(output, self.soa_record(params, command, zone_name))
                            has_soa = True
                        elif ('sshfp' == record):
                            output = self._append(output, self.sshfp_record(params, command, zone_name))
                        elif ('tlsa' == record):
                            output = self._append(output, self.tlsa_record(params, command, zone_name))
                        elif ('tlsa_cert' == record):
                            output = self._append(output, self.tlsa_cert_record(params, command, zone_name))
                        elif ('smimea' == record):
                            output = self._append(output, self.smimea_record(params, command, zone_name))
                        elif ('acme' == record):
                            output = self._append(output, self.acme_record(params, command, zone_name))
                        elif ('caa' == record):
                            output = self._append(output, self.caa_record(params, command, zone_name))
                        elif ('dkim' == record):
                            output = self._append(output, self.dkim_record(params, command, zone_name))
                        elif ('dmarc' == record):
                            output = self._append(output, self.dmarc_record(params, command, zone_name))
                        elif ('pgp' == record):
                            output = self._append(output, self.pgp_record(params, command, zone_name))
                        elif ('ldap' == record):
                            output = self._append(output, self.ldap_record(params, command, zone_name))
                        elif ('include' == record):
                            include, included_soa = self.include(params, command, zone_name, zone_file_path, param_vars)
                            output = self._append(output, include)
                            has_soa = (has_soa or included_soa)
                        else:
                            self._error('Unknown command: ', command, '\n')
                    elif ('=' in command):
                        if ((0 == len(output)) or ('\n' == output[-1]) and ('\n' == input[0:1])):
                            input = input[1:]
                            if ('\n' == input[0:1]):
                                input = input[1:]
                        var, value = command.split('=', 1)
                        self.vars[var.strip()] = value.strip()
                        self._debug('set: ', var, ' = ', value, '\n')
                    elif (command in param_vars):
                        output = self._append(output, param_vars[command])
                    elif (command in self.vars):
                        output = self._append(output, self.vars[command])
                    else:
                        self._error('Unknown variable: ', command, '\n')
                else:
                    output += input
                    break
        return output, has_soa

    def process_zone_file(self, zone_file_path, out_file_path):
        self.vars = {}
        param_vars = {}

        zone_name = os.path.basename(zone_file_path)
        output, has_soa = self._process_zone_file(zone_file_path, zone_name, param_vars)

        if (not has_soa):
            self._error('Zone file does not contain {{soa:}}\n')

        if (out_file_path):
            out_file_path = os.path.join(out_file_path, zone_name) if (os.path.isdir(out_file_path)) else out_file_path
            with open(out_file_path, 'w') as out_file:
                out_file.write(output)
        else:
            print(output)

    def run(self):
        self._validate_config(self.args.zone_file_path)
        self.process_zone_file(self.args.zone_file_path, self.args.out_file_path)


def debug_hook(type, value, tb):
    if hasattr(sys, 'ps1') or not sys.stderr.isatty():
        # we are in interactive mode or we don't have a tty-like
        # device, so we call the default hook
        sys.__excepthook__(type, value, tb)
    else:
        import pdb
        import traceback
        # we are NOT in interactive mode, print the exception...
        traceback.print_exception(type, value, tb)
        print()
        # ...then start the debugger in post-mortem mode.
        pdb.pm()

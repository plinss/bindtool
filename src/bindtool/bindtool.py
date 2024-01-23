"""BindTool does variable substitution and generates special Resource Records."""

from __future__ import annotations

import argparse
import base64
import binascii
import glob
import hashlib
import json
import os
import re
import subprocess  # noqa: S404
import sys
import unicodedata
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, IO, NoReturn, TYPE_CHECKING, cast

import DNS

import ldap

if (TYPE_CHECKING):
    from collections.abc import Collection, Sequence
    from types import TracebackType


def module_version(module: str) -> str:
    """Get version of installed module."""
    try:
        from importlib.metadata import version
        return version(module)
    except ModuleNotFoundError:
        from pkg_resources import get_distribution
        return get_distribution(module).version


class Args:
    """Command line arguments."""

    zone_file_path: str
    out_file_path: (str | None)
    debug: bool
    config_path: str


class BindToolError(Exception):
    """General error."""

    pass


class BindTool:
    """Bind9 zone file processor."""

    args: Args
    script_dir: str
    script_name: str
    config: dict[str, Any]
    config_dir: str
    vars: dict[str, str]
    certificates: dict[str, (bytes | None)]
    public_keys: dict[str, (bytes | None)]

    _config_defaults: Mapping[str, Any]

    def __init__(self) -> None:
        script_entry = sys.argv[0]
        self.script_dir = os.path.dirname(os.path.realpath(script_entry))
        self.script_name = os.path.basename(script_entry)

        argparser = argparse.ArgumentParser(description='Preprocess bind zone files')
        argparser.add_argument('--version', action='version', version='%(prog)s ' + module_version('bindtool'))
        argparser.add_argument('zone_file_path')
        argparser.add_argument('out_file_path', nargs='?')
        argparser.add_argument('-d', '--debug',
                               action='store_true', dest='debug', default=False,
                               help='print detailed debugging information to stdout')
        argparser.add_argument('-c', '--config',
                               dest='config_path', default=f'{self.script_name}.json', metavar='CONFIG_PATH',
                               help='Specify file path for config')
        self.args = cast(Args, argparser.parse_args())
        if (not self.args.zone_file_path):
            argparser.print_usage()

        if (self.args.debug):
            sys.excepthook = _debug_hook

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
                    'host': None,
                    'ttl': None,
                },
                'include': {
                    'file': None,
                },
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

        self.certificates = {}
        self.public_keys = {}

    def _zone_config_file_path(self, config_file_path: str, zone_name: str) -> str:
        config_dir, config_filename = os.path.split(config_file_path)
        if ('.' in config_filename):
            name, extension = config_filename.rsplit('.', 1)
            return os.path.join(config_dir, f'{name}.{zone_name}.{extension}')
        return os.path.join(config_dir, f'{name}.{zone_name}')

    def _merge_config(self, base: (dict[str, Any] | None), extra: Mapping[str, Any]) -> dict[str, Any]:
        if (base is None):
            base = {}
        for name, value in extra.items():
            if (isinstance(value, Mapping)):
                base[name] = self._merge_config(base.get(name), value)
            else:
                base[name] = value
        return base

    def _load_config_file(self, config_file_path: str) -> dict[str, Any]:
        if (os.path.isfile(config_file_path)):
            try:
                with open(config_file_path) as config_file:
                    self._debug('Loading config', config_file_path)
                    return json.load(config_file)
            except Exception as error:
                self._error('Error reading config file', config_file_path, self._indent(error))
        return {}

    def _load_config(self, file_path: str, search_paths: Sequence[str], zone_name: str) -> tuple[dict[str, Any], str]:
        search_paths = [''] if (os.path.isabs(file_path)) else search_paths
        for search_path in reversed(search_paths):
            config_file_path = os.path.join(search_path, file_path)
            zone_config_file_path = self._zone_config_file_path(config_file_path, zone_name)
            if (os.path.isfile(config_file_path) or os.path.isfile(zone_config_file_path)):
                config = None
                config = self._merge_config(config, self._load_config_file(config_file_path))
                config = self._merge_config(config, self._load_config_file(zone_config_file_path))
                return (config, os.path.dirname(os.path.abspath(config_file_path)))
        return ({}, '')

    def _indent(self, message: (str | Exception), *, indent: str = '    ') -> str:
        lines = str(message).split('\n')
        return ('\n' + '\n'.join((indent + line) for line in lines))

    def _message(self, *args, sep: str = ' ', end: str = '\n') -> str:
        return (sep.join((str(arg, 'utf-8', 'replace') if isinstance(arg, bytes) else str(arg)) for arg in args) + end)

    def _quoted(self, *args) -> str:
        return ('"' + '", "'.join(args) + '"')

    def _command(self, command: str) -> str:
        return f'{{{command}}}'

    def _debug(self, *args, sep: str = ' ', end: str = '\n') -> None:
        if (self.args.debug):
            sys.stdout.write(self._message(*args, sep=sep, end=end))

    def _warn(self, *args, sep: str = ' ', end: str = '\n') -> None:
        message = self._message(*args, sep=sep, end=end)
        sys.stderr.write(f'WARNING: {message}')

    def _error(self, *args, sep: str = ' ', end: str = '\n') -> NoReturn:
        message = self._message(*args, sep=sep, end=end)
        sys.stderr.write(f'ERROR: {message}')
        raise BindToolError(message)

    def _config(self, section_name: str, *, key: (str | None) = None,
                default: (str | int | Mapping[str, Any] | None) = None) -> (str | int | Mapping[str, Any]):
        return self.config.get(section_name, {}).get(key, default) if (key) else self.config.get(section_name, {})

    def _defaults(self, type: str, *, fill: (Mapping[str, Any] | None) = None) -> dict[str, Any]:
        out: dict[str, Any] = (dict(fill) if (fill) else {})
        defaults = cast(dict, self._config('defaults', key=type, default={}))
        for key, value in defaults.items():
            out[key] = str(value) if (value is not None) else ''
        return out

    def _ldap(self, key: str) -> str:
        return cast(str, self._config('ldap', key=key))

    def _directory(self, file_type: str) -> str:
        directory = cast(str, self._config('directories', key=file_type, default=''))
        return os.path.normpath(os.path.join(self.config_dir, directory)) if (directory) else directory

    def _key_type_suffix(self, key_type: (str | None)) -> str:
        return cast(str, self._config('key_type_suffixes', key=key_type, default=''))

    def _file_name(self, file_type: str) -> str:
        return cast(str, self._config('file_names', key=file_type, default=''))

    def _file_path(self, file_type: str, file_name: str, *, key_type: (str | None) = None, replace_wildcard: bool = True, **kwargs) -> str:
        if (os.path.isabs(file_name)):
            return file_name
        if (self._directory(file_type) is not None):
            directory = self._directory(file_type).format(name=file_name, key_type=key_type, suffix=self._key_type_suffix(key_type), **kwargs)
            file_name = self._file_name(file_type).format(name=file_name, key_type=key_type, suffix=self._key_type_suffix(key_type), **kwargs)
            return os.path.join(directory, file_name.replace('*', '_') if (replace_wildcard) else file_name)
        return ''

    def _find_file(self, file_types: (str | Sequence[str]), file_name: str, *, key_type: (str | None) = None, **kwargs) -> (str | None):
        if (isinstance(file_types, str)):
            file_types = [file_types]
        for file_type in file_types:
            if (file_type):
                file_path = os.path.expanduser(self._file_path(file_type, file_name, key_type=key_type, **kwargs))
                if (os.path.isfile(file_path)):
                    return file_path
        return None

    def _find_files(self, file_types: (str | Sequence[str]), file_name: str, *, key_type: (str | None) = None, **kwargs) -> Sequence[str]:
        result = []
        if (isinstance(file_types, str)):
            file_types = [file_types]
        for file_type in file_types:
            if (file_type):
                file_paths = glob.glob(os.path.expanduser(self._file_path(file_type, file_name, key_type=key_type, replace_wildcard=False, **kwargs)))
                for file_path in sorted(file_paths):
                    if (os.path.isfile(file_path) and (file_path not in result)):
                        result.append(file_path)
        return result

    def _makedir(self, dir_path: str, *, chmod: (int | None) = None, warn: bool = True) -> None:
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
                            self._warn('Unable to set directory mode for', dir_path, self._indent(error))
            except Exception as error:
                if (warn):
                    self._warn('Unable to create directory', dir_path, self._indent(error))

    def _open_file(self, file_path: str, *, mode: str = 'r', chmod: int = 0o666, warn: bool = True) -> IO:
        def opener(file_path: str, flags: int) -> int:
            return os.open(file_path, flags, mode=chmod)
        if (('w' in mode) or ('a' in mode)):
            self._makedir(os.path.dirname(file_path), chmod=chmod, warn=warn)
        return open(file_path, mode, opener=opener)

    def _copy_defaults(self, source: Mapping[str, Any], target: dict[str, Any]) -> None:
        for key, value in source.items():
            if (key not in target):
                target[key] = value
            else:
                if (isinstance(value, dict) and isinstance(target[key], dict)):
                    self._copy_defaults(value, target[key])

    def _validate_config(self, zone_file_path: str) -> None:
        if ('directories' not in self.config):
            self.config['directories'] = {}
        for legacy_directory in ['certificate_path', 'private_key_path', 'backup_key_path', 'previous_key_path',
                                 'dkim_path', 'ssh_path', 'acme_path', 'include_path']:
            if (legacy_directory in self.config):
                self.config['directories'][legacy_directory[:-5]] = self.config[legacy_directory]
                del self.config[legacy_directory]
        self._copy_defaults(self._config_defaults, self.config)
        self.config['directories']['zone_file'] = os.path.dirname(os.path.realpath(zone_file_path))

    def _split_command(self, command: str) -> tuple[str, Sequence[tuple[str, str]]]:
        parts: list[tuple[str, str]] = []
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

    def _parse_args(self, type: str, args: Sequence[tuple[str, str]], param_names: Sequence[str],
                    defaults: Mapping[str, str], prefixes: Mapping[str, str], command: str) -> dict[str, str]:
        _args = list(args)
        _names = list(param_names)
        params = self._defaults(type, fill=defaults)
        while (0 < len(_args)):
            name, value = _args.pop(0)
            if (name):
                if (name in _names):
                    _names.remove(name)
            else:
                if (0 < len(_names)):
                    name = _names.pop(0)
                else:
                    self._error('Non-positional record arguments must have names', self._command(command))
            if (value or (name not in params)):
                params[name] = value
        for name, prefix in prefixes.items():
            if ((name in params) and params[name]):
                params[name] = prefix + params[name]
        return params

    def _wrap(self, value: str, *, length: int = 80, threshold: int = 100) -> str:
        if (len(value) <= threshold):
            return value
        output = '(\n'
        while (0 < len(value)):
            output += f'\t\t{value[:length]}\n'
            value = value[length:]
        output += '\t)'
        return output

    def _record(self, format: str, params: Mapping[str, str], *, end: str = '\n', **kwargs) -> str:
        _params = dict(params)
        for key, value in kwargs.items():
            _params[key] = value
        return (format.format(**_params) + end)

    def _generic_rr(self, params: Mapping[str, str], type: int, value: bytes) -> str:
        return self._record('{host}{ttl}\tTYPE{type}\t\\# {len} {data}', params, type=type, len=len(value), data=self._wrap(self._hex(value)))

    def _txt_rr(self, params: Mapping[str, str], host: str, data: str, *, length: int = 80, threshold: int = 100) -> str:
        output = self._record('{host}{ttl}\tTXT\t', params, host=host, end='')
        if (len(data) <= min(255, threshold)):
            return f'{output}{self._quoted(data)}\n'
        length = min(255, length)
        output += '(\n'
        while (0 < len(data)):
            output += f'\t\t"{data[:length]}"\n'
            data = data[length:]
        output += '\t)\n'
        return output

    def _hex(self, value: bytes) -> str:
        return binascii.hexlify(value).decode('ascii')

    def _base64(self, value: bytes) -> str:
        return base64.b64encode(value).decode('ascii')

    def _sha1(self, value: bytes) -> str:
        return hashlib.sha1(value).hexdigest()

    def _sha256(self, value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def _sha512(self, value: bytes) -> str:
        return hashlib.sha512(value).hexdigest()

    def _openssl(self, *args: str) -> bytes:
        return subprocess.check_output(['openssl', *args], stderr=subprocess.DEVNULL)  # noqa: S603, S607

    def _load_certificates(self, cert_file_name: str, type: str, *, username: str = '') -> Sequence[bytes]:
        certificates: list[bytes] = []
        username = (f'{username}@' if (username) else username)
        key_types = [type] if (type) else ['rsa', 'ecdsa']

        for key_type in key_types:
            cert_file_path = self._find_file('certificate', cert_file_name, key_type=key_type, username=username)
            if (cert_file_path):
                if (cert_file_path in self.certificates):
                    certificate = self.certificates[cert_file_path]
                else:
                    self._debug('Loading certificate', cert_file_path)
                    certificate = self._openssl('x509', '-in', cert_file_path, '-outform', 'DER')
                    self.certificates[cert_file_path] = certificate
                if (certificate):
                    certificates.append(certificate)
        if (not certificates):
            self._warn('Certificate file', cert_file_name, 'not found')
        return certificates

    def _extract_public_key(self, public_key_pem: bytes) -> (bytes | None):
        if (public_key_pem):
            match = re.match(r'-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----', public_key_pem.decode('ascii'), re.DOTALL)
            if (match):
                return base64.b64decode(match.group(1))
        return None

    def _public_key_from_certificate(self, cert_file_path: str) -> (bytes | None):
        return self._extract_public_key(self._openssl('x509', '-in', cert_file_path, '-pubkey', '-noout'))

    def _public_key_from_private_key(self, private_key_path: str, passphrase: str) -> (bytes | None):
        pass_arg = ['-passin', f'pass:{passphrase}'] if (passphrase) else []
        try:
            return self._extract_public_key(self._openssl('rsa', '-in', private_key_path, '-pubout', *pass_arg))
        except Exception:
            return self._extract_public_key(self._openssl('ec', '-in', private_key_path, '-pubout', *pass_arg))

    def _load_public_keys(self, cert_file_name: str, type: str, passphrase: str, *, username: str = '') -> Sequence[bytes]:
        public_keys: list[bytes] = []
        username = (f'{username}@' if (username) else username)
        key_types = [type] if (type) else ['rsa', 'ecdsa']

        for key_type in key_types:
            cert_file_path = self._find_file('certificate', cert_file_name, key_type=key_type, username=username)
            if (cert_file_path):
                if (cert_file_path in self.public_keys):
                    public_key = self.public_keys[cert_file_path]
                else:
                    self._debug('Loading public key from certificate', cert_file_path)
                    public_key = self._public_key_from_certificate(cert_file_path)
                    self.public_keys[cert_file_path] = public_key
                if (public_key):
                    public_keys.append(public_key)
            else:
                private_key_path = self._find_file(['private_key', 'backup_key', 'previous_key'],
                                                   cert_file_name, key_type=key_type, username=username)
                if (private_key_path):
                    if (private_key_path in self.public_keys):
                        public_key = self.public_keys[private_key_path]
                    else:
                        self._debug('Loading public key from private key', private_key_path)
                        public_key = self._public_key_from_private_key(private_key_path, passphrase)
                        self.public_keys[private_key_path] = public_key
                    if (public_key):
                        public_keys.append(public_key)
        if (not public_keys):
            self._warn('Certificate or private key file not found for', cert_file_name)
        return public_keys

    def _alternative_names_from_certificate(self, cert_file_name: str, type: str) -> Collection[str]:
        alternative_names = set()
        key_types = [type] if (type) else ['rsa', 'ecdsa']
        regex = re.compile(r'.*X509v3 Subject Alternative Name:\s*([^\n]*)\n.*', re.DOTALL)

        for key_type in key_types:
            cert_file_path = self._find_file('certificate', cert_file_name, key_type=key_type, username='')
            if (cert_file_path):
                self._debug('Loading alternative names from certificate', cert_file_path)
                match = regex.match(self._openssl('x509', '-in', cert_file_path, '-noout', '-text').decode('ascii'))
                if (match):
                    alternative_names |= {name[4:] for name in match.group(1).split(', ') if name.startswith('DNS:')}
        return alternative_names

    def _load_dkim_public_key(self, selector: str, domain: str) -> (bytes | None):
        key_file_path = self._find_file('dkim', domain, selector=selector, domain=domain)
        if (key_file_path):
            return self._openssl('rsa', '-in', key_file_path, '-outform', 'DER', '-pubout')
        self._warn('DKIM key', selector, 'for', domain, 'not found')
        return None

    def _validate(self, params: dict[str, str], command: str, param: str, values: Sequence[str], *, convert: (Sequence[str] | None) = None) -> None:
        if (params[param] not in values):
            self._error('Unknown value', self._quoted(params[param]), 'for', param, 'in', self._command(command), '.\n',
                        'Must be one of:', self._quoted(*values))
        if (convert):
            params[param] = convert[values.index(params[param])]

    def _validate_numeric(self, params: Mapping[str, str], command: str, param: str) -> None:
        if (not params[param].isdigit()):
            self._error(param.title(), 'must be numeric for', self._command(command))

    def soa_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
        params = self._parse_args('soa', args, ['primary_server', 'admin', 'refresh', 'retry', 'expire', 'minimum', 'master_server', 'ttl'],
                                  {}, {'ttl': '\t'}, command)
        if ('primary_server' not in params):
            self._error('soa record must specify primary server', self._command(command))
        if ('admin' not in params):
            self._error('soa record must specify admin', self._command(command))
        if (not params['primary_server'].endswith('.')):
            params['primary_server'] += '.'
        params['admin'] = params['admin'].replace('@', '.')
        if (not params['admin'].endswith('.')):
            params['admin'] += '.'

        master_server = params['master_server'] if (params['master_server']) else params['primary_server']
        existing_serial = 0
        try:
            response = DNS.Request().req(server=master_server, name=zone_name, qtype='SOA')
            existing_serial = response.answers[0]['data'][2][1] if (response and ('NOERROR' == response.header['status'])) else 0
            self._debug('Found serial number', existing_serial)
        except Exception as error:
            self._error('Unable to perform DNS SOA query', self._indent(error))
        serial = max(int(datetime.now(timezone.utc).strftime('%Y%m%d00')), existing_serial + 1)
        self._debug('Using serial number', serial)

        return self._record('@{ttl}\tSOA\t{primary_server} {admin} {serial} {refresh} {retry} {expire} {minimum}', params, serial=serial)

    def sshfp_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
        params = self._parse_args('sshfp', args, ['host', 'key_file', 'ttl', 'type'], {}, {'ttl': '\t'}, command)
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
                    with open(key_file_path) as key_file:
                        key_text = key_file.read().split(' ')
                        key = base64.b64decode(key_text[1])

                        output += self._record('{host}{ttl}\tSSHFP\t{key_type} 1 {digest}', params, key_type=key_type_value[key_type], digest=self._sha1(key))
                        output += self._record('{host}{ttl}\tSSHFP\t{key_type} 2 {digest}', params, key_type=key_type_value[key_type], digest=self._sha256(key))
                except Exception as error:
                    self._error('Unable to read key from', key_file_path, self._indent(error))
        if (not found):
            self._warn('No SSH keys found for:', params['host'], 'matching:', params['key_file'])
        return output

    def tlsa_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
        params = self._parse_args('tlsa', args, ['port', 'host', 'cert_file', 'usage', 'selector', 'proto', 'ttl', 'type', 'pass'],
                                  {'cert_file': zone_name}, {'host': '.', 'ttl': '\t'}, command)
        self._validate_numeric(params, command, 'port')
        self._validate(params, command, 'usage', ('pkix-ta', 'pkix-ee', 'dane-ta', 'dane-ee'), convert=('0', '1', '2', '3'))
        self._validate(params, command, 'selector', ('cert', 'spki'), convert=('0', '1'))
        self._validate(params, command, 'proto', ('tcp', 'udp', 'sctp', 'dccp'))
        self._validate(params, command, 'type', ('', 'rsa', 'ecdsa'))

        if ('cert' == params['selector']):
            payloads = self._load_certificates(params['cert_file'], params['type'])
        else:
            payloads = self._load_public_keys(params['cert_file'], params['type'], params['pass'])
        if (not payloads):
            return ''

        output = ''
        for payload in payloads:
            output += self._record('_{port}._{proto}{host}{ttl}\tTLSA\t{usage} {selector} 1 {digest}', params, digest=self._sha256(payload))
            output += self._record('_{port}._{proto}{host}{ttl}\tTLSA\t{usage} {selector} 2 {digest}', params, digest=self._sha512(payload))
        return output

    def tlsa_cert_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
        params = self._parse_args('tlsa_cert', args, ['port', 'cert_file', 'usage', 'selector', 'proto', 'ttl', 'type'],
                                  {'cert_file': zone_name}, {'ttl': '\t'}, command)
        self._validate_numeric(params, command, 'port')
        self._validate(params, command, 'usage', ('pkix-ta', 'pkix-ee', 'dane-ta', 'dane-ee'), convert=('0', '1', '2', '3'))
        self._validate(params, command, 'selector', ('cert', 'spki'), convert=('0', '1'))
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
        for host in sorted(alternative_names):
            if ('*' in host):
                self._error('tlsa_cert record certificate', params['cert_file'], 'must not include wildcard hosts')
            for payload in payloads:
                output += self._record('_{port}._{proto}.{host}{ttl}\tTLSA\t{usage} {selector} 1 {digest}', params, host=host, digest=self._sha256(payload))
                output += self._record('_{port}._{proto}.{host}{ttl}\tTLSA\t{usage} {selector} 2 {digest}', params, host=host, digest=self._sha512(payload))
        return output

    def _email_hash(self, localpart: str) -> str:
        if ('*' != localpart):
            localpart = unicodedata.normalize('NFC', localpart)
            return self._sha256(localpart.encode('utf-8'))[:56]
        return localpart

    def smimea_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
        params = self._parse_args('smimea', args, ['user', 'host', 'cert_file', 'usage', 'selector', 'ttl', 'type', 'pass'],
                                  {'cert_file': zone_name}, {'host': '.', 'ttl': '\t'}, command)
        if ('user' not in params):
            self._error('smimea record must specify user', self._command(command))
        self._validate(params, command, 'usage', ('pkix-ta', 'pkix-ee', 'dane-ta', 'dane-ee'), convert=('0', '1', '2', '3'))
        self._validate(params, command, 'selector', ('cert', 'spki'), convert=('0', '1'))
        self._validate(params, command, 'type', ('', 'rsa', 'ecdsa'))

        userhash = self._email_hash(params['user'])

        if ('cert' == params['selector']):
            payloads = self._load_certificates(params['cert_file'], params['type'], username=params['user'])
        else:
            payloads = self._load_public_keys(params['cert_file'], params['type'], params['pass'], username=params['user'])
        if (not payloads):
            return ''

        output = ''
        for payload in payloads:
            if ('cert' == params['selector']):
                output += self._record('{userhash}._smimecert{host}{ttl}\tSMIMEA\t{usage} {selector} 0 {cert}', params, userhash=userhash,
                                       cert=self._wrap(self._hex(payload), length=120, threshold=125))
            output += self._record('{userhash}._smimecert{host}{ttl}\tSMIMEA\t{usage} {selector} 1 {digest}', params, userhash=userhash,
                                   digest=self._sha256(payload))
            output += self._record('{userhash}._smimecert{host}{ttl}\tSMIMEA\t{usage} {selector} 2 {digest}', params, userhash=userhash,
                                   digest=self._sha512(payload))
        return output

    def acme_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
        params = self._parse_args('acme', args, ['challenge_file', 'ttl'], {'challenge_file': zone_name}, {'ttl': '\t'}, command)

        output = ''
        challenge_path = self._find_file('acme', params['challenge_file'])
        if (challenge_path):
            with open(challenge_path) as challenge_file:
                challenges = json.load(challenge_file)
            for host in challenges:
                output += self._txt_rr(params, '_acme-challenge.' + (host[2:] if (host.startswith('*.')) else host) + '.', challenges[host])
        else:
            self._debug('ACME challenge file', params['challenge_file'], 'not found')
        return output

    def _caa_rr(self, params: Mapping[str, str], flag: str, tag: str, caname: str) -> str:
        return self._generic_rr(params, 257,
                                int(flag).to_bytes(1, byteorder='big') + len(tag).to_bytes(1, byteorder='big')
                                + tag.encode('ascii') + caname.encode('ascii'))

    def caa_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
        params = self._parse_args('caa', args, ['tag', 'caname', 'host', 'flag', 'ttl'], {}, {'ttl': '\t'}, command)
        if ('tag' not in params):
            self._error('caa record must specify tag', self._command(command))
        if ('caname' not in params):
            self._error('caa record must specify caname', self._command(command))
        self._validate_numeric(params, command, 'flag')

        return self._caa_rr(params, params['flag'], params['tag'], params['caname'])

    def dkim_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
        params = self._parse_args('dkim', args, ['selector', 'domain', 'host', 'ttl'], {'domain': zone_name}, {'host': '.', 'ttl': '\t'}, command)
        dkim_public_key = self._load_dkim_public_key(params['selector'], params['domain'])
        if (dkim_public_key):
            host = self._record('{selector}._domainkey{host}', params, end='')
            return self._txt_rr(params, host, f'v=DKIM1; k=rsa; p={self._base64(dkim_public_key)}')
        return ''

    def dmarc_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
        params = self._parse_args('dmarc', args, ['policy', 'rua', 'ruf', 'subdomain_policy', 'options', 'dkim_alignment', 'spf_alignment',
                                                  'report_format', 'interval', 'percent', 'host', 'ttl'],
                                  {}, {'host': '.', 'ttl': '\t'}, command)

        if (params['rua']):
            params['rua'] = 'rua=' + ','.join([f'mailto:{addr.strip()}' for addr in params['rua'].split(',')]) + '; '
        if (params['ruf']):
            params['ruf'] = 'ruf=' + ','.join([f'mailto:{addr.strip()}' for addr in params['ruf'].split(',')]) + '; '

        self._validate(params, command, 'policy', ('none', 'quarantine', 'reject'))
        self._validate(params, command, 'subdomain_policy', ('none', 'quarantine', 'reject'))
        self._validate(params, command, 'options', ('all', 'any', 'dkim', 'spf'), convert=('0', '1', 'd', 's'))
        self._validate(params, command, 'dkim_alignment', ('strict', 'relaxed'), convert=('s', 'r'))
        self._validate(params, command, 'spf_alignment', ('strict', 'relaxed'), convert=('s', 'r'))
        self._validate(params, command, 'report_format', ('afrf', 'iodef'))
        self._validate_numeric(params, command, 'interval')
        self._validate_numeric(params, command, 'percent')

        return self._txt_rr(params, self._record('_dmarc{host}', params, end=''),
                            self._record('v=DMARC1; p={policy}; {rua}{ruf}sp={subdomain_policy}; fo={options}; adkim={dkim_alignment}; aspf={spf_alignment}; '
                                         'rf={report_format}; ri={interval}; pct={percent};', params, end=''))

    def pgp_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
        self._error('pgp records not yet supported')
        return ''

    def _decode_ldap_entry(self, zone: tuple[str, Mapping[str, Sequence[bytes]]]) -> Mapping[str, Sequence[str]]:
        return {key: [value.decode('ascii') for value in values] for key, values in zone[1].items()}

    def _load_ldap_zones(self, zone_name: str) -> Sequence[Mapping[str, Sequence[str]]]:
        zones: list[Mapping[str, Sequence[str]]] = []
        cache_file_path = self._file_path('cache', zone_name)
        if (os.path.isfile(cache_file_path)):
            try:
                with open(cache_file_path) as cache_file:
                    zones = json.load(cache_file)
            except Exception as error:
                self._error('Error reading cache file', cache_file_path, self._indent(error))

        if (not self._ldap('url')):
            self._error('No LDAP server configured')

        ldap_server = ldap.initialize(self._ldap('url'))  # type: ignore
        try:
            ldap_server.bind_s(self._ldap('user_dn'), self._ldap('password'), ldap.AUTH_SIMPLE)  # type: ignore
        except Exception as error:
            self._warn('Unable to bind to LDAP server', self._indent(error))
            return zones

        try:
            ldap_entries = ldap_server.search_s(f'zoneName={zone_name}.,{self._ldap("search_base")}',
                                                ldap.SCOPE_SUBTREE, filterstr=self._ldap('filter'))  # type: ignore
            zones = [self._decode_ldap_entry(zone) for zone in ldap_entries]
            try:
                with self._open_file(cache_file_path, mode='w', chmod=0o600) as cache_file:
                    json.dump(zones, cache_file)
            except Exception as error:
                self._error('Unable to save ldap cache', self._indent(error))

        except Exception:
            pass
        return zones

    def ldap_record(self, args: Sequence[tuple[str, str]], command: str, zone_name: str) -> str:
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

        def _record(record_type: str, host: str, data: str) -> str:
            if ('TXT' == record_type):
                return self._txt_rr({'ttl': ''}, host, data)
            data = data.replace(';', r'\;')
            return f'{host}\t{record_type}\t{data}\n'

        for zone in zones:
            if (zone['zoneName'][0] == (zone_name + '.')):
                for record_type in record_type_map:
                    if (record_type in zone):
                        for record in zone[record_type]:
                            output += _record(record_type_map[record_type], zone['relativeDomainName'][0], record)
        return output

    def include(self, args: Sequence[tuple[str, str]], command: str, zone_name: str, zone_file_path: str, param_vars: Mapping[str, str]) -> tuple[str, bool]:
        params = self._parse_args('include', args, ['file'], {}, {}, command)
        if (not params['file']):
            self._error('Include file path not specified')
        hold_include_parent = self.config['directories'].get('include_parent')
        self.config['directories']['include_parent'] = os.path.dirname(os.path.realpath(zone_file_path))
        include_file_paths = self._find_files(['include_parent', 'zone_file', 'include'], params['file'])
        self.config['directories']['include_parent'] = hold_include_parent
        if ((not include_file_paths) and ('*' not in params['file']) and ('?' not in params['file'])):
            self._error('Include file', self._quoted(params['file']), 'not found')
        del params['file']
        local_vars: dict[str, str] = {}
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
        return (output, has_soa)

    def _append(self, output: str, records: str) -> str:
        last_line_index = output.rfind('\n')
        if (-1 < last_line_index):
            last_line = output[last_line_index + 1:]
            if (';' in last_line):
                return output + '\n;'.join(records.split('\n'))
        return output + records

    def _process_zone_file(self, zone_file_path: str, zone_name: str, param_vars: Mapping[str, str]) -> tuple[str, bool]:
        if (not os.path.isfile(zone_file_path)):
            self._error('Zone file', self._quoted(zone_file_path), 'not found')

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
                    self._debug('processing', self._command(command))
                    if (command.startswith('-')):
                        pass
                    elif (re.match(r'^[a-z_]+:', command)):
                        if (((0 == len(output)) or ('\n' == output[-1])) and ('\n' == input[0:1])):
                            input = input[1:]
                        record, args = self._split_command(command)
                        if ('soa' == record):
                            output = self._append(output, self.soa_record(args, command, zone_name))
                            has_soa = True
                        elif ('sshfp' == record):
                            output = self._append(output, self.sshfp_record(args, command, zone_name))
                        elif ('tlsa' == record):
                            output = self._append(output, self.tlsa_record(args, command, zone_name))
                        elif ('tlsa_cert' == record):
                            output = self._append(output, self.tlsa_cert_record(args, command, zone_name))
                        elif ('smimea' == record):
                            output = self._append(output, self.smimea_record(args, command, zone_name))
                        elif ('acme' == record):
                            output = self._append(output, self.acme_record(args, command, zone_name))
                        elif ('caa' == record):
                            output = self._append(output, self.caa_record(args, command, zone_name))
                        elif ('dkim' == record):
                            output = self._append(output, self.dkim_record(args, command, zone_name))
                        elif ('dmarc' == record):
                            output = self._append(output, self.dmarc_record(args, command, zone_name))
                        elif ('pgp' == record):
                            output = self._append(output, self.pgp_record(args, command, zone_name))
                        elif ('ldap' == record):
                            output = self._append(output, self.ldap_record(args, command, zone_name))
                        elif ('include' == record):
                            include, included_soa = self.include(args, command, zone_name, zone_file_path, param_vars)
                            output = self._append(output, include)
                            has_soa = (has_soa or included_soa)
                        else:
                            self._error('Unknown command:', command)
                    elif ('=' in command):
                        if ((0 == len(output)) or ('\n' == output[-1]) and ('\n' == input[0:1])):
                            input = input[1:]
                            if ('\n' == input[0:1]):
                                input = input[1:]
                        var, value = command.split('=', 1)
                        self.vars[var.strip()] = value.strip()
                        self._debug('set:', var, '=', value)
                    elif (command in param_vars):
                        output = self._append(output, param_vars[command])
                    elif (command in self.vars):
                        output = self._append(output, self.vars[command])
                    else:
                        self._error('Unknown variable:', command)
                else:
                    output += input
                    break
        return (output, has_soa)

    def process_zone_file(self, zone_file_path: str, out_file_path: (str | None)) -> None:
        """Process a zone file."""
        self.vars = {}
        param_vars: dict[str, str] = {}

        zone_name = os.path.basename(zone_file_path)
        output, has_soa = self._process_zone_file(zone_file_path, zone_name, param_vars)

        if (not has_soa):
            self._error('Zone file does not contain {{soa:}}')

        if (out_file_path):
            out_file_path = os.path.join(out_file_path, zone_name) if (os.path.isdir(out_file_path)) else out_file_path
            with open(out_file_path, 'w') as out_file:
                out_file.write(output)
        else:
            print(output)

    def run(self) -> None:
        """Main entry point."""
        self._validate_config(self.args.zone_file_path)
        self.process_zone_file(self.args.zone_file_path, self.args.out_file_path)


def _debug_hook(type: type[BaseException], value: BaseException, traceback: (TracebackType | None) = None) -> None:  # noqa: KWP001
    """Hook for starting the debugger in debug mode."""
    if (hasattr(sys, 'ps1') or not sys.stderr.isatty()):
        # we are in interactive mode or we don't have a tty-like
        # device, so we call the default hook
        sys.__excepthook__(type, value, traceback)
    else:
        import pdb
        import traceback as tb
        # we are NOT in interactive mode, print the exception...
        tb.print_exception(type, value, traceback)
        print()
        # ...then start the debugger in post-mortem mode.
        pdb.pm()

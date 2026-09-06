#
# -*- coding: utf-8 -*-
#
# This file is part of reclass
#
# Support for ansible-vault encrypted values in the inventory.
#
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import hashlib
import os
import posix

from six import string_types

from reclass.errors import ReclassException

VAULT_HEADER = '$ANSIBLE_VAULT'
REDACTED = '***VAULTED***'

MODE_REDACT = 'redact'
MODE_DECRYPT = 'decrypt'
MODE_KEEP = 'keep'
MODES = (MODE_REDACT, MODE_DECRYPT, MODE_KEEP)


class VaultError(ReclassException):

    def __init__(self, msg, rc=posix.EX_CONFIG):
        # tbFlag=False: ReclassException would otherwise call
        # traceback.format_exc(), which captures whatever exception is
        # currently being handled -- typically the KeyError that the storage
        # cache raises internally -- and prints it above the real message.
        super(VaultError, self).__init__(rc=rc, msg=msg, tbFlag=False)


class VaultedString(str):
    '''A string that came out of an ansible-vault blob.

    The marker exists so that reclass does not run its reference parser over
    the result: a decrypted secret may legitimately contain the reference
    sentinels ('${', '}') or the escape character, which would otherwise be
    interpreted instead of taken literally.

    The marker is consumed in reclass.values.value.Value and never reaches
    the output.
    '''
    pass


# Lazily built VaultLib, and a cache of already decrypted values keyed by a
# digest of their ciphertext. Vault uses PBKDF2 with 10000 iterations, so
# decrypting the same value once per class that references it is expensive.
_vault_lib = None
_cache = {}


def _construct_vault_tag(loader, node):
    # "ansible-vault encrypt_string" tags its output with !vault, which a
    # SafeLoader refuses to construct. The tag carries nothing reclass needs:
    # the payload is the vault envelope itself, which is_vaulted() recognises
    # on its own. So unwrap it to the plain scalar.
    return loader.construct_scalar(node)


def vault_aware_loader(base):
    '''Return a subclass of base that accepts ansible's !vault tag.

    A subclass rather than a mutation of base, so that other users of the
    same loader class in the process are left alone.
    '''
    loader = type(str('VaultSafeLoader'), (base,), {})
    loader.add_constructor('!vault', _construct_vault_tag)
    return loader


def is_vaulted(value):
    return (isinstance(value, string_types)
            and value.lstrip().startswith(VAULT_HEADER))


def _password_file():
    '''Locate the vault password file.

    ANSIBLE_VAULT_PASSWORD_FILE first, then ansible's own configuration so
    that a vault_password_file set in ansible.cfg is honoured as well.

    --vault-password-file and --vault-id are deliberately out of reach:
    ansible does not pass them down to an external inventory script, so
    there is nothing for reclass to read.
    '''
    path = os.environ.get('ANSIBLE_VAULT_PASSWORD_FILE')
    if path:
        return path
    try:
        from ansible.constants import config
        return config.get_config_value('DEFAULT_VAULT_PASSWORD_FILE')
    except Exception:
        return None


def _get_vault_lib():
    global _vault_lib
    if _vault_lib is not None:
        return _vault_lib

    try:
        from ansible.parsing.dataloader import DataLoader
        from ansible.parsing.vault import VaultLib, get_file_vault_secret
    except ImportError:
        raise VaultError('vault_mode is "{0}" but ansible is not installed; '
                         'install ansible or set vault_mode to "{1}"'
                         .format(MODE_DECRYPT, MODE_REDACT))

    path = _password_file()
    if not path:
        raise VaultError('vault_mode is "{0}" but no vault password file is '
                         'configured: set ANSIBLE_VAULT_PASSWORD_FILE, or '
                         'vault_password_file in ansible.cfg'
                         .format(MODE_DECRYPT))
    path = os.path.expanduser(path)

    # get_file_vault_secret handles a plain password file and an executable
    # that prints the password, exactly the way ansible itself does, and
    # rejects a missing or empty one.
    try:
        secret = get_file_vault_secret(filename=path, loader=DataLoader())
        secret.load()
    except Exception as e:
        raise VaultError('cannot use vault password file {0}: {1}'
                         .format(path, e.__class__.__name__))

    _vault_lib = VaultLib([('default', secret)])
    return _vault_lib


def decrypt(ciphertext, where=None):
    key = hashlib.sha256(ciphertext.encode('utf-8')).hexdigest()
    if key not in _cache:
        lib = _get_vault_lib()
        try:
            # The decode belongs inside the try: a secret that is not valid
            # UTF-8 must surface as a VaultError like any other failure, not
            # as a bare UnicodeDecodeError.
            _cache[key] = lib.decrypt(
                ciphertext.encode('utf-8')).decode('utf-8')
        except Exception as e:
            # Reports the location and the exception class only: neither the
            # password, the ciphertext nor the plaintext may reach a log.
            raise VaultError('failed to decrypt vault value{0}: {1}'
                             .format(_at(where), e.__class__.__name__))
    return _cache[key]


def _at(where):
    return ' at {0}'.format(where) if where else ''


def _transform(value, mode, where=None):
    if mode == MODE_REDACT:
        return VaultedString(REDACTED)
    if mode == MODE_KEEP:
        return VaultedString(value)
    return VaultedString(decrypt(value, where))


def _walk(data, mode, uri, path):
    if is_vaulted(data):
        key = ':'.join(path)
        where = '{0} ({1})'.format(key, uri) if uri else key
        return _transform(data, mode, where or uri)
    if isinstance(data, dict):
        return dict((k, _walk(v, mode, uri, path + [str(k)]))
                    for k, v in data.items())
    if isinstance(data, list):
        return [_walk(v, mode, uri, path + [str(i)])
                for i, v in enumerate(data)]
    return data


def apply_mode(data, mode, uri=None):
    '''Recursively replace ansible-vault blobs in data according to mode.

    Returns a new structure; the input is left untouched. uri, when given,
    is quoted in decryption errors alongside the key path of the offending
    value, so that a failure points at a file instead of nothing.
    '''
    if mode not in MODES:
        raise VaultError('unknown vault_mode {0!r}, expected one of {1}'
                         .format(mode, ', '.join(MODES)))
    return _walk(data, mode, uri, [])

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
        super(VaultError, self).__init__(rc=rc, msg=msg)


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


def _get_vault_lib():
    global _vault_lib
    if _vault_lib is not None:
        return _vault_lib

    try:
        from ansible.parsing.vault import VaultLib, VaultSecret
    except ImportError:
        raise VaultError('vault_mode is "{0}" but ansible is not installed; '
                         'install ansible or set vault_mode to "{1}"'
                         .format(MODE_DECRYPT, MODE_REDACT))

    path = os.environ.get('ANSIBLE_VAULT_PASSWORD_FILE')
    if not path:
        raise VaultError('vault_mode is "{0}" but '
                         'ANSIBLE_VAULT_PASSWORD_FILE is not set'
                         .format(MODE_DECRYPT))
    path = os.path.expanduser(path)

    try:
        with open(path, 'rb') as fp:
            password = fp.read().strip()
    except IOError as e:
        raise VaultError('cannot read ANSIBLE_VAULT_PASSWORD_FILE {0}: {1}'
                         .format(path, e))
    if not password:
        raise VaultError('ANSIBLE_VAULT_PASSWORD_FILE {0} is empty'
                         .format(path))

    _vault_lib = VaultLib([('default', VaultSecret(password))])
    return _vault_lib


def decrypt(ciphertext):
    key = hashlib.sha256(ciphertext.encode('utf-8')).hexdigest()
    if key not in _cache:
        lib = _get_vault_lib()
        try:
            plaintext = lib.decrypt(ciphertext.encode('utf-8'))
        except Exception as e:
            # Deliberately reports only the exception class: neither the
            # password nor the ciphertext must reach a log.
            raise VaultError('failed to decrypt vault value: {0}'
                             .format(e.__class__.__name__))
        _cache[key] = plaintext.decode('utf-8')
    return _cache[key]


def _transform(value, mode):
    if mode == MODE_REDACT:
        return VaultedString(REDACTED)
    if mode == MODE_KEEP:
        return VaultedString(value)
    return VaultedString(decrypt(value))


def apply_mode(data, mode):
    '''Recursively replace ansible-vault blobs in data according to mode.

    Returns a new structure; the input is left untouched.
    '''
    if mode not in MODES:
        raise VaultError('unknown vault_mode {0!r}, expected one of {1}'
                         .format(mode, ', '.join(MODES)))
    if is_vaulted(data):
        return _transform(data, mode)
    if isinstance(data, dict):
        return dict((k, apply_mode(v, mode)) for k, v in data.items())
    if isinstance(data, list):
        return [apply_mode(v, mode) for v in data]
    return data

#
# -*- coding: utf-8 -*-
#
# This file is part of reclass
#
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import tempfile
import unittest

from reclass import vault

# A syntactically valid vault envelope. Not decryptable, but enough to
# exercise detection and redaction without requiring ansible.
VAULTED = ('$ANSIBLE_VAULT;1.1;AES256\n'
           '3131313131313131313131313131313131313131313131313131313131313131\n')


class TestVaultDetection(unittest.TestCase):

    def test_is_vaulted_true(self):
        self.assertTrue(vault.is_vaulted(VAULTED))

    def test_is_vaulted_true_with_leading_whitespace(self):
        self.assertTrue(vault.is_vaulted('\n  ' + VAULTED))

    def test_is_vaulted_false_for_plain_string(self):
        self.assertFalse(vault.is_vaulted('hello'))

    def test_is_vaulted_false_for_non_string(self):
        self.assertFalse(vault.is_vaulted(42))
        self.assertFalse(vault.is_vaulted(None))
        self.assertFalse(vault.is_vaulted({'a': 1}))


class TestApplyModeWithoutAnsible(unittest.TestCase):

    def test_redact_nested_structure(self):
        data = {'a': {'b': [VAULTED, 'plain']}, 'c': 1}
        out = vault.apply_mode(data, vault.MODE_REDACT)
        self.assertEqual(out, {'a': {'b': [vault.REDACTED, 'plain']}, 'c': 1})

    def test_redact_marks_result_as_vaulted_string(self):
        out = vault.apply_mode({'a': VAULTED}, vault.MODE_REDACT)
        self.assertIsInstance(out['a'], vault.VaultedString)

    def test_apply_mode_does_not_mutate_input(self):
        data = {'a': VAULTED}
        vault.apply_mode(data, vault.MODE_REDACT)
        self.assertEqual(data['a'], VAULTED)

    def test_keep_preserves_ciphertext(self):
        out = vault.apply_mode({'a': VAULTED}, vault.MODE_KEEP)
        self.assertEqual(str(out['a']), VAULTED)
        self.assertIsInstance(out['a'], vault.VaultedString)

    def test_unknown_mode_raises(self):
        self.assertRaises(vault.VaultError, vault.apply_mode, {}, 'bogus')

    def test_plain_data_untouched(self):
        data = {'a': [1, 'two', None, True], 'b': {'c': 'd'}}
        self.assertEqual(vault.apply_mode(data, vault.MODE_REDACT), data)


class TestVaultDecrypt(unittest.TestCase):

    def setUp(self):
        try:
            from ansible.parsing.vault import VaultLib, VaultSecret
        except ImportError:
            self.skipTest('ansible is not installed')
        fd, self.pwfile = tempfile.mkstemp(prefix='reclass-vault-test-')
        with os.fdopen(fd, 'w') as fp:
            fp.write('testpassword\n')
        self.saved_env = os.environ.get('ANSIBLE_VAULT_PASSWORD_FILE')
        os.environ['ANSIBLE_VAULT_PASSWORD_FILE'] = self.pwfile
        vault._vault_lib = None
        vault._cache = {}
        lib = VaultLib([('default', VaultSecret(b'testpassword'))])
        # The plaintext deliberately contains reference sentinels: a decrypted
        # secret must never be fed back through the reclass parser.
        self.plaintext = 's3cr3t-${not-a-ref}-\\x'
        self.ciphertext = lib.encrypt(
            self.plaintext.encode('utf-8')).decode('utf-8')

    def tearDown(self):
        os.unlink(self.pwfile)
        if self.saved_env is None:
            os.environ.pop('ANSIBLE_VAULT_PASSWORD_FILE', None)
        else:
            os.environ['ANSIBLE_VAULT_PASSWORD_FILE'] = self.saved_env
        vault._vault_lib = None
        vault._cache = {}

    def test_decrypt_roundtrip(self):
        out = vault.apply_mode({'a': self.ciphertext}, vault.MODE_DECRYPT)
        self.assertEqual(str(out['a']), self.plaintext)
        self.assertIsInstance(out['a'], vault.VaultedString)

    def test_decrypt_result_is_cached(self):
        vault.apply_mode({'a': self.ciphertext}, vault.MODE_DECRYPT)
        self.assertEqual(len(vault._cache), 1)
        vault.apply_mode({'b': self.ciphertext}, vault.MODE_DECRYPT)
        self.assertEqual(len(vault._cache), 1)

    def test_missing_password_file_raises(self):
        os.environ.pop('ANSIBLE_VAULT_PASSWORD_FILE', None)
        vault._vault_lib = None
        self.assertRaises(vault.VaultError, vault.apply_mode,
                          {'a': self.ciphertext}, vault.MODE_DECRYPT)

    def test_wrong_password_raises_without_leaking(self):
        with open(self.pwfile, 'w') as fp:
            fp.write('wrongpassword\n')
        vault._vault_lib = None
        vault._cache = {}
        try:
            vault.apply_mode({'a': self.ciphertext}, vault.MODE_DECRYPT)
        except vault.VaultError as e:
            self.assertNotIn('wrongpassword', str(e))
        else:
            self.fail('VaultError not raised')


if __name__ == '__main__':
    unittest.main()

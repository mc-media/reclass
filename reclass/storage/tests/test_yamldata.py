#
# -*- coding: utf-8 -*-
#
# This file is part of reclass (http://github.com/madduck/reclass)
#
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from reclass.storage.yamldata import YamlData

import unittest

class TestYamlData(unittest.TestCase):

    def setUp(self):
        lines = [ 'classes:',
                  '  - testdir.test1',
                  '  - testdir.test2',
                  '  - test3',
                  '',
                  'environment: base',
                  '',
                  'parameters:',
                  '  _TEST_:',
                  '    alpha: 1',
                  '    beta: two' ]
        self.data = '\n'.join(lines)
        self.yamldict = { 'classes': [ 'testdir.test1', 'testdir.test2', 'test3' ],
                          'environment': 'base',
                          'parameters': { '_TEST_': { 'alpha': 1, 'beta': 'two' } }
                        }

    def test_yaml_from_string(self):
        res = YamlData.from_string(self.data, 'testpath')
        self.assertEqual(res.uri, 'testpath')
        self.assertEqual(res.get_data(), self.yamldict)

    # Note: Parameters.as_dict() returns Value objects until the entity has
    # been interpolated. entity.interpolate(None) is what turns them into
    # plain rendered scalars, so every assertion below goes through it.

    def test_vault_value_is_redacted_by_default(self):
        from reclass.settings import Settings
        lines = [ 'parameters:',
                  '  secret: |',
                  '    $ANSIBLE_VAULT;1.1;AES256',
                  '    3131313131313131313131313131313131313131',
                  '  plain: keepme' ]
        y = YamlData.from_string('\n'.join(lines), 'testpath')
        entity = y.get_entity('testnode', 'testnode', Settings())
        entity.interpolate(None)
        rendered = entity.parameters.as_dict()
        self.assertEqual(rendered['secret'].strip(), '***VAULTED***')
        self.assertEqual(rendered['plain'], 'keepme')

    def test_reference_to_vault_value_is_redacted(self):
        # This is the pattern used in the mcm-doc-website inventory: a secret
        # is interpolated into the middle of a larger config string.
        from reclass.settings import Settings
        lines = [ 'parameters:',
                  '  secret: |',
                  '    $ANSIBLE_VAULT;1.1;AES256',
                  '    3131313131313131313131313131313131313131',
                  '  config: client_secret="${secret}"' ]
        y = YamlData.from_string('\n'.join(lines), 'testpath')
        entity = y.get_entity('testnode', 'testnode', Settings())
        entity.interpolate(None)
        rendered = entity.parameters.as_dict()
        self.assertIn('***VAULTED***', rendered['config'])
        self.assertNotIn('$ANSIBLE_VAULT', rendered['config'])

    def test_vault_value_kept_in_keep_mode(self):
        from reclass.settings import Settings
        lines = [ 'parameters:',
                  '  secret: |',
                  '    $ANSIBLE_VAULT;1.1;AES256',
                  '    3131313131313131313131313131313131313131' ]
        y = YamlData.from_string('\n'.join(lines), 'testpath')
        entity = y.get_entity('testnode', 'testnode',
                              Settings({'vault_mode': 'keep'}))
        entity.interpolate(None)
        rendered = entity.parameters.as_dict()
        self.assertTrue(rendered['secret'].startswith('$ANSIBLE_VAULT'))


    def test_vault_tagged_scalar_is_redacted(self):
        # This is the form "ansible-vault encrypt_string" produces. A plain
        # SafeLoader refuses the !vault tag outright.
        from reclass.settings import Settings
        lines = [ 'parameters:',
                  '  secret: !vault |',
                  '    $ANSIBLE_VAULT;1.1;AES256',
                  '    3131313131313131313131313131313131313131' ]
        y = YamlData.from_string('\n'.join(lines), 'testpath')
        entity = y.get_entity('testnode', 'testnode', Settings())
        entity.interpolate(None)
        self.assertEqual(
            entity.parameters.as_dict()['secret'].strip(), '***VAULTED***')


if __name__ == '__main__':
    unittest.main()

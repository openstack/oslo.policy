# Copyright (c) 2015 OpenStack Foundation.
# All Rights Reserved.

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from unittest import mock

from oslotest import base as test_base

from oslo_policy import _checks
from oslo_policy import _parser
from oslo_policy.tests import base


class ParseCheckTestCase(test_base.BaseTestCase):
    def test_false(self):
        result = _parser._parse_check('!')

        self.assertIsInstance(result, _checks.FalseCheck)

    def test_true(self):
        result = _parser._parse_check('@')

        self.assertIsInstance(result, _checks.TrueCheck)

    @mock.patch.object(_parser, 'LOG')
    def test_bad_rule(self, mock_log):
        result = _parser._parse_check('foobar')

        self.assertIsInstance(result, _checks.FalseCheck)
        mock_log.exception.assert_called_once()

    @mock.patch.object(_checks, 'registered_checks', {})
    @mock.patch.object(_parser, 'LOG')
    def test_no_handler(self, mock_log):
        result = _parser._parse_check('no:handler')

        self.assertIsInstance(result, _checks.FalseCheck)
        mock_log.error.assert_called()

    @mock.patch.object(
        _checks,
        'registered_checks',
        {
            'spam': mock.Mock(return_value='spam_check'),
            None: mock.Mock(return_value='none_check'),
        },
    )
    def test_check(self):
        result = _parser._parse_check('spam:handler')

        self.assertEqual('spam_check', result)
        _checks.registered_checks['spam'].assert_called_once_with(
            'spam', 'handler'
        )
        self.assertFalse(_checks.registered_checks[None].called)

    @mock.patch.object(
        _checks,
        'registered_checks',
        {
            None: mock.Mock(return_value='none_check'),
        },
    )
    def test_check_default(self):
        result = _parser._parse_check('spam:handler')

        self.assertEqual('none_check', result)
        _checks.registered_checks[None].assert_called_once_with(
            'spam', 'handler'
        )


class ParseListRuleTestCase(test_base.BaseTestCase):
    def test_empty(self):
        result = _parser._parse_list_rule([])

        self.assertIsInstance(result, _checks.TrueCheck)
        self.assertEqual('@', str(result))

    @mock.patch.object(_parser, '_parse_check', base.FakeCheck)
    def test_oneele_zeroele(self):
        result = _parser._parse_list_rule([[]])

        self.assertIsInstance(result, _checks.FalseCheck)
        self.assertEqual('!', str(result))

    @mock.patch.object(_parser, '_parse_check', base.FakeCheck)
    def test_oneele_bare(self):
        result = _parser._parse_list_rule(['rule'])

        self.assertIsInstance(result, base.FakeCheck)
        assert isinstance(result, base.FakeCheck)  # narrow type
        self.assertEqual('rule', result.result)
        self.assertEqual('rule', str(result))

    @mock.patch.object(_parser, '_parse_check', base.FakeCheck)
    def test_oneele_oneele(self):
        result = _parser._parse_list_rule([['rule']])

        self.assertIsInstance(result, base.FakeCheck)
        assert isinstance(result, base.FakeCheck)  # narrow type
        self.assertEqual('rule', result.result)
        self.assertEqual('rule', str(result))

    @mock.patch.object(_parser, '_parse_check', base.FakeCheck)
    def test_oneele_multi(self):
        result = _parser._parse_list_rule([['rule1', 'rule2']])

        self.assertIsInstance(result, _checks.AndCheck)
        assert isinstance(result, _checks.AndCheck)  # narrow type
        self.assertEqual(2, len(result.rules))
        for i, value in enumerate(['rule1', 'rule2']):
            rule = result.rules[i]
            self.assertIsInstance(rule, base.FakeCheck)
            assert isinstance(rule, base.FakeCheck)  # narrow type
            self.assertEqual(value, rule.result)
        self.assertEqual('(rule1 and rule2)', str(result))

    @mock.patch.object(_parser, '_parse_check', base.FakeCheck)
    def test_multi_oneele(self):
        result = _parser._parse_list_rule([['rule1'], ['rule2']])

        self.assertIsInstance(result, _checks.OrCheck)
        assert isinstance(result, _checks.OrCheck)  # narrow type
        self.assertEqual(2, len(result.rules))
        for i, value in enumerate(['rule1', 'rule2']):
            rule = result.rules[i]
            self.assertIsInstance(rule, base.FakeCheck)
            assert isinstance(rule, base.FakeCheck)  # narrow type
            self.assertEqual(value, rule.result)
        self.assertEqual('(rule1 or rule2)', str(result))

    @mock.patch.object(_parser, '_parse_check', base.FakeCheck)
    def test_multi_multi(self):
        result = _parser._parse_list_rule(
            [['rule1', 'rule2'], ['rule3', 'rule4']]
        )

        self.assertIsInstance(result, _checks.OrCheck)
        assert isinstance(result, _checks.OrCheck)  # narrow type
        self.assertEqual(2, len(result.rules))
        for i, values in enumerate([['rule1', 'rule2'], ['rule3', 'rule4']]):
            rule = result.rules[i]
            self.assertIsInstance(rule, _checks.AndCheck)
            assert isinstance(rule, _checks.AndCheck)  # narrow type
            self.assertEqual(2, len(rule.rules))
            for j, value in enumerate(values):
                sub_rule = rule.rules[j]
                assert isinstance(sub_rule, base.FakeCheck)  # narrow type
                self.assertIsInstance(sub_rule, base.FakeCheck)
                self.assertEqual(value, sub_rule.result)
        self.assertEqual(
            '((rule1 and rule2) or (rule3 and rule4))', str(result)
        )


class ParseTokenizeTestCase(test_base.BaseTestCase):
    @mock.patch.object(_parser, '_parse_check', lambda x: x)
    def test_tokenize(self):
        exemplar = (
            '(( ( ((() And)) or ) (check:%(miss)s) not)) '
            '\'a-string\' "another-string"'
        )
        expected = [
            ('(', '('),
            ('(', '('),
            ('(', '('),
            ('(', '('),
            ('(', '('),
            ('(', '('),
            (')', ')'),
            ('and', 'And'),
            (')', ')'),
            (')', ')'),
            ('or', 'or'),
            (')', ')'),
            ('(', '('),
            ('check', 'check:%(miss)s'),
            (')', ')'),
            ('not', 'not'),
            (')', ')'),
            (')', ')'),
            ('string', 'a-string'),
            ('string', 'another-string'),
        ]

        result = list(_parser._parse_tokenize(exemplar))

        self.assertEqual(expected, result)


class ParseStateTestCase(test_base.BaseTestCase):
    def test_init(self):
        state = _parser.ParseState()

        self.assertEqual([], state.tokens)
        self.assertEqual([], state.values)

    def test_reduce_no_match(self):
        """Test that reduce() does nothing when no patterns match."""
        state = _parser.ParseState()
        state.tokens = ['unknown_token']
        state.values = ['unknown_value']

        state.reduce()

        # Should remain unchanged
        self.assertEqual(['unknown_token'], state.tokens)
        self.assertEqual(['unknown_value'], state.values)

    def test_reduce_parentheses(self):
        """Test reduction of parenthesized check."""
        state = _parser.ParseState()
        check = _checks.TrueCheck()
        state.tokens = ['(', 'check', ')']
        state.values = ['(', check, ')']

        state.reduce()

        self.assertEqual(['check'], state.tokens)
        self.assertEqual([check], state.values)

    def test_reduce_and_check(self):
        """Test reduction of AND expression with two checks."""
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()
        state.tokens = ['check', 'and', 'check']
        state.values = [check1, 'and', check2]

        state.reduce()

        self.assertEqual(['and_expr'], state.tokens)
        self.assertEqual(1, len(state.values))
        result = state.values[0]
        self.assertIsInstance(result, _checks.AndCheck)
        assert isinstance(result, _checks.AndCheck)  # narrow type
        self.assertEqual(2, len(result.rules))
        self.assertEqual(check1, result.rules[0])
        self.assertEqual(check2, result.rules[1])

    def test_reduce_or_check(self):
        """Test reduction of OR expression with two checks."""
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()
        state.tokens = ['check', 'or', 'check']
        state.values = [check1, 'or', check2]

        state.reduce()

        self.assertEqual(['or_expr'], state.tokens)
        self.assertEqual(1, len(state.values))
        result = state.values[0]
        self.assertIsInstance(result, _checks.OrCheck)
        assert isinstance(result, _checks.OrCheck)  # narrow type
        self.assertEqual(2, len(result.rules))
        self.assertEqual(check1, result.rules[0])
        self.assertEqual(check2, result.rules[1])

    def test_reduce_not_check(self):
        """Test reduction of NOT expression."""
        state = _parser.ParseState()
        check = _checks.TrueCheck()
        state.tokens = ['not', 'check']
        state.values = ['not', check]

        state.reduce()

        self.assertEqual(['check'], state.tokens)
        self.assertEqual(1, len(state.values))
        result = state.values[0]
        self.assertIsInstance(result, _checks.NotCheck)
        assert isinstance(result, _checks.NotCheck)  # narrow type
        self.assertEqual(check, result.rule)

    def test_shift(self):
        state = _parser.ParseState()

        with mock.patch.object(_parser.ParseState, 'reduce') as mock_reduce:
            state.shift('token', 'value')

            self.assertEqual(['token'], state.tokens)
            self.assertEqual(['value'], state.values)
            mock_reduce.assert_called_once_with()

    def test_result_empty(self):
        state = _parser.ParseState()

        self.assertRaises(ValueError, lambda: state.result)

    def test_result_unreduced(self):
        state = _parser.ParseState()
        state.tokens = ['tok1', 'tok2']
        state.values = ['val1', 'val2']

        self.assertRaises(ValueError, lambda: state.result)

    def test_result(self):
        state = _parser.ParseState()
        check = _checks.TrueCheck()
        state.tokens = ['token']
        state.values = [check]

        self.assertEqual(check, state.result)

    def test_result_invalid_value(self):
        state = _parser.ParseState()
        state.tokens = ['token']
        state.values = ['not_a_check']  # String instead of BaseCheck

        self.assertRaises(ValueError, lambda: state.result)

    def test_wrap_check(self):
        state = _parser.ParseState()
        check = _checks.TrueCheck()

        result = state._wrap_check('(', check, ')')

        self.assertEqual([('check', check)], result)

    def test_make_and_expr(self):
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()

        result = state._make_and_expr(check1, 'and', check2)

        self.assertEqual(1, len(result))
        token, value = result[0]
        self.assertEqual('and_expr', token)
        self.assertIsInstance(value, _checks.AndCheck)
        assert isinstance(value, _checks.AndCheck)  # narrow type
        self.assertEqual(2, len(value.rules))
        self.assertEqual(check1, value.rules[0])
        self.assertEqual(check2, value.rules[1])

    def test_extend_and_expr(self):
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()
        and_expr = _checks.AndCheck([check1])

        result = state._extend_and_expr(and_expr, 'and', check2)

        self.assertEqual(1, len(result))
        token, value = result[0]
        self.assertEqual('and_expr', token)
        self.assertIsInstance(value, _checks.AndCheck)
        assert isinstance(value, _checks.AndCheck)  # narrow type
        self.assertEqual(2, len(value.rules))
        self.assertEqual(check1, value.rules[0])
        self.assertEqual(check2, value.rules[1])

    def test_make_or_expr(self):
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()

        result = state._make_or_expr(check1, 'or', check2)

        self.assertEqual(1, len(result))
        token, value = result[0]
        self.assertEqual('or_expr', token)
        self.assertIsInstance(value, _checks.OrCheck)
        assert isinstance(value, _checks.OrCheck)  # narrow type
        self.assertEqual(2, len(value.rules))
        self.assertEqual(check1, value.rules[0])
        self.assertEqual(check2, value.rules[1])

    def test_extend_or_expr(self):
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()
        or_expr = _checks.OrCheck([check1])

        result = state._extend_or_expr(or_expr, 'or', check2)

        self.assertEqual(1, len(result))
        token, value = result[0]
        self.assertEqual('or_expr', token)
        self.assertIsInstance(value, _checks.OrCheck)
        assert isinstance(value, _checks.OrCheck)  # narrow type
        self.assertEqual(2, len(value.rules))
        self.assertEqual(check1, value.rules[0])
        self.assertEqual(check2, value.rules[1])

    def test_make_not_expr(self):
        state = _parser.ParseState()
        check = _checks.TrueCheck()

        result = state._make_not_expr('not', check)

        self.assertEqual(1, len(result))
        token, value = result[0]
        self.assertEqual('check', token)
        self.assertIsInstance(value, _checks.NotCheck)
        assert isinstance(value, _checks.NotCheck)  # narrow type
        self.assertEqual(check, value.rule)


class ParseTextRuleTestCase(test_base.BaseTestCase):
    def test_empty(self):
        result = _parser._parse_text_rule('')

        self.assertIsInstance(result, _checks.TrueCheck)

    @mock.patch.object(
        _parser,
        '_parse_tokenize',
        return_value=[('tok1', 'val1'), ('tok2', 'val2')],
    )
    @mock.patch.object(_parser.ParseState, 'shift')
    @mock.patch.object(_parser.ParseState, 'result', 'result')
    def test_shifts(self, mock_shift, mock_parse_tokenize):
        result = _parser._parse_text_rule('test rule')

        self.assertEqual('result', result)
        mock_parse_tokenize.assert_called_once_with('test rule')
        mock_shift.assert_has_calls(
            [mock.call('tok1', 'val1'), mock.call('tok2', 'val2')]
        )

    @mock.patch.object(_parser, 'LOG', new=mock.Mock())
    @mock.patch.object(_parser, '_parse_tokenize', return_value=[])
    def test_fail(self, mock_parse_tokenize):
        result = _parser._parse_text_rule('test rule')

        self.assertIsInstance(result, _checks.FalseCheck)
        mock_parse_tokenize.assert_called_once_with('test rule')

    def test_A_or_B_or_C(self):
        result = _parser._parse_text_rule('@ or ! or @')
        self.assertEqual('(@ or ! or @)', str(result))

    def test_A_or_B_and_C(self):
        result = _parser._parse_text_rule('@ or ! and @')
        self.assertEqual('(@ or (! and @))', str(result))

    def test_A_and_B_or_C(self):
        result = _parser._parse_text_rule('@ and ! or @')
        self.assertEqual('((@ and !) or @)', str(result))

    def test_A_and_B_and_C(self):
        result = _parser._parse_text_rule('@ and ! and @')
        self.assertEqual('(@ and ! and @)', str(result))

    def test_A_or_B_or_C_or_D(self):
        result = _parser._parse_text_rule('@ or ! or @ or !')
        self.assertEqual('(@ or ! or @ or !)', str(result))

    def test_A_or_B_or_C_and_D(self):
        result = _parser._parse_text_rule('@ or ! or @ and !')
        self.assertEqual('(@ or ! or (@ and !))', str(result))

    def test_A_or_B_and_C_or_D(self):
        result = _parser._parse_text_rule('@ or ! and @ or !')
        self.assertEqual('(@ or (! and @) or !)', str(result))

    def test_A_or_B_and_C_and_D(self):
        result = _parser._parse_text_rule('@ or ! and @ and !')
        self.assertEqual('(@ or (! and @ and !))', str(result))

    def test_A_and_B_or_C_or_D(self):
        result = _parser._parse_text_rule('@ and ! or @ or !')
        self.assertEqual('((@ and !) or @ or !)', str(result))

    def test_A_and_B_or_C_and_D(self):
        result = _parser._parse_text_rule('@ and ! or @ and !')
        self.assertEqual('((@ and !) or (@ and !))', str(result))

    def test_A_and_B_and_C_or_D(self):
        result = _parser._parse_text_rule('@ and ! and @ or !')
        self.assertEqual('((@ and ! and @) or !)', str(result))

    def test_A_and_B_and_C_and_D(self):
        result = _parser._parse_text_rule('@ and ! and @ and !')
        self.assertEqual('(@ and ! and @ and !)', str(result))

    def test_A_and_B_or_C_with_not_1(self):
        result = _parser._parse_text_rule('not @ and ! or @')
        self.assertEqual('((not @ and !) or @)', str(result))

    def test_A_and_B_or_C_with_not_2(self):
        result = _parser._parse_text_rule('@ and not ! or @')
        self.assertEqual('((@ and not !) or @)', str(result))

    def test_A_and_B_or_C_with_not_3(self):
        result = _parser._parse_text_rule('@ and ! or not @')
        self.assertEqual('((@ and !) or not @)', str(result))

    def test_A_and_B_or_C_with_group_1(self):
        for expression in [
            '( @ ) and ! or @',
            '@ and ( ! ) or @',
            '@ and ! or ( @ )',
            '( @ ) and ! or ( @ )',
            '@ and ( ! ) or ( @ )',
            '( @ ) and ( ! ) or ( @ )',
            '( @ and ! ) or @',
            '( ( @ ) and ! ) or @',
            '( @ and ( ! ) ) or @',
            '( ( @ and ! ) ) or @',
            '( @ and ! or @ )',
        ]:
            result = _parser._parse_text_rule(expression)
            self.assertEqual('((@ and !) or @)', str(result))

    def test_A_and_B_or_C_with_group_2(self):
        result = _parser._parse_text_rule('@ and ( ! or @ )')
        self.assertEqual('(@ and (! or @))', str(result))

    def test_A_and_B_or_C_with_group_and_not_1(self):
        for expression in [
            'not ( @ ) and ! or @',
            'not @ and ( ! ) or @',
            'not @ and ! or ( @ )',
            '( not @ ) and ! or @',
            '( not @ and ! ) or @',
            '( not @ and ! or @ )',
        ]:
            result = _parser._parse_text_rule(expression)
            self.assertEqual('((not @ and !) or @)', str(result))

    def test_A_and_B_or_C_with_group_and_not_2(self):
        result = _parser._parse_text_rule('not @ and ( ! or @ )')
        self.assertEqual('(not @ and (! or @))', str(result))

    def test_A_and_B_or_C_with_group_and_not_3(self):
        result = _parser._parse_text_rule('not ( @ and ! or @ )')
        self.assertEqual('not ((@ and !) or @)', str(result))

    def test_A_and_B_or_C_with_group_and_not_4(self):
        for expression in [
            '( @ ) and not ! or @',
            '@ and ( not ! ) or @',
            '@ and not ( ! ) or @',
            '@ and not ! or ( @ )',
            '( @ and not ! ) or @',
            '( @ and not ! or @ )',
        ]:
            result = _parser._parse_text_rule(expression)
            self.assertEqual('((@ and not !) or @)', str(result))

    def test_A_and_B_or_C_with_group_and_not_5(self):
        result = _parser._parse_text_rule('@ and ( not ! or @ )')
        self.assertEqual('(@ and (not ! or @))', str(result))

    def test_A_and_B_or_C_with_group_and_not_6(self):
        result = _parser._parse_text_rule('@ and not ( ! or @ )')
        self.assertEqual('(@ and not (! or @))', str(result))

    def test_A_and_B_or_C_with_group_and_not_7(self):
        for expression in [
            '( @ ) and ! or not @',
            '@ and ( ! ) or not @',
            '@ and ! or not ( @ )',
            '@ and ! or ( not @ )',
            '( @ and ! ) or not @',
            '( @ and ! or not @ )',
        ]:
            result = _parser._parse_text_rule(expression)
            self.assertEqual('((@ and !) or not @)', str(result))

    def test_A_and_B_or_C_with_group_and_not_8(self):
        result = _parser._parse_text_rule('@ and ( ! or not @ )')
        self.assertEqual('(@ and (! or not @))', str(result))


class ParseRuleTestCase(test_base.BaseTestCase):
    @mock.patch.object(_parser, '_parse_text_rule', return_value='text rule')
    @mock.patch.object(_parser, '_parse_list_rule', return_value='list rule')
    def test_parse_rule_string(
        self, mock_parse_list_rule, mock_parse_text_rule
    ):
        result = _parser.parse_rule('a string')

        self.assertEqual('text rule', result)
        self.assertFalse(mock_parse_list_rule.called)
        mock_parse_text_rule.assert_called_once_with('a string')

    @mock.patch.object(_parser, '_parse_text_rule', return_value='text rule')
    @mock.patch.object(_parser, '_parse_list_rule', return_value='list rule')
    def test_parse_rule_list(self, mock_parse_list_rule, mock_parse_text_rule):
        result = _parser.parse_rule([['a'], ['list']])

        self.assertEqual('list rule', result)
        self.assertFalse(mock_parse_text_rule.called)
        mock_parse_list_rule.assert_called_once_with([['a'], ['list']])

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
    def test_tokenize(self):
        exemplar = (
            '(( ( ((() And)) or ) (rule:context_is_admin) not)) '
            '\'a-string\' "another-string"'
        )

        result = list(_parser._parse_tokenize(exemplar))

        expected = [
            _parser.LeftParamToken('('),
            _parser.LeftParamToken('('),
            _parser.LeftParamToken('('),
            _parser.LeftParamToken('('),
            _parser.LeftParamToken('('),
            _parser.LeftParamToken('('),
            _parser.RightParamToken(')'),
            _parser.AndToken('And'),
            _parser.RightParamToken(')'),
            _parser.RightParamToken(')'),
            _parser.OrToken('or'),
            _parser.RightParamToken(')'),
            _parser.LeftParamToken('('),
            _parser.CheckToken(_checks.RuleCheck('rule', 'context_is_admin')),
            _parser.RightParamToken(')'),
            _parser.NotToken('not'),
            _parser.RightParamToken(')'),
            _parser.RightParamToken(')'),
            _parser.StringToken('a-string'),
            _parser.StringToken('another-string'),
        ]

        self.assertEqual(expected, result)


class ParseStateTestCase(test_base.BaseTestCase):
    def test_init(self):
        state = _parser.ParseState()

        self.assertEqual([], state.stack)

    def test_reduce_no_match(self):
        """Test that reduce() does nothing when no patterns match."""
        state = _parser.ParseState()
        # Create a token that won't match any reduction pattern
        unknown_token = _parser.StringToken('unknown_value')
        state.stack = [unknown_token]

        state.reduce()

        # Should remain unchanged
        self.assertEqual([unknown_token], state.stack)

    def test_reduce_parentheses(self):
        """Test reduction of parenthesized check."""
        state = _parser.ParseState()
        check = _checks.TrueCheck()
        state.stack = [
            _parser.LeftParamToken('('),
            _parser.CheckToken(check),
            _parser.RightParamToken(')'),
        ]

        state.reduce()

        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.CheckToken)
        self.assertEqual(check, result_token.value)

    def test_reduce_and_check(self):
        """Test reduction of AND expression with two checks."""
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()
        state.stack = [
            _parser.CheckToken(check1),
            _parser.AndToken('and'),
            _parser.CheckToken(check2),
        ]

        state.reduce()

        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.AndExprToken)
        result = result_token.value
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
        state.stack = [
            _parser.CheckToken(check1),
            _parser.OrToken('or'),
            _parser.CheckToken(check2),
        ]

        state.reduce()

        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.OrExprToken)
        result = result_token.value
        self.assertIsInstance(result, _checks.OrCheck)
        assert isinstance(result, _checks.OrCheck)  # narrow type
        self.assertEqual(2, len(result.rules))
        self.assertEqual(check1, result.rules[0])
        self.assertEqual(check2, result.rules[1])

    def test_reduce_not_check(self):
        """Test reduction of NOT expression."""
        state = _parser.ParseState()
        check = _checks.TrueCheck()
        state.stack = [_parser.NotToken('not'), _parser.CheckToken(check)]

        state.reduce()

        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.CheckToken)
        result = result_token.value
        self.assertIsInstance(result, _checks.NotCheck)
        assert isinstance(result, _checks.NotCheck)  # narrow type
        self.assertEqual(check, result.rule)

    def test_shift(self):
        state = _parser.ParseState()

        with mock.patch.object(_parser.ParseState, 'reduce') as mock_reduce:
            token = _parser.StringToken('value')
            state.shift(token)

            self.assertEqual([token], state.stack)
            mock_reduce.assert_called_once_with()

    def test_result_empty(self):
        state = _parser.ParseState()

        self.assertRaises(ValueError, lambda: state.result)

    def test_result_unreduced(self):
        state = _parser.ParseState()
        state.stack = [
            _parser.StringToken('val1'),
            _parser.StringToken('val2'),
        ]

        self.assertRaises(ValueError, lambda: state.result)

    def test_result(self):
        state = _parser.ParseState()
        check = _checks.TrueCheck()
        state.stack = [_parser.CheckToken(check)]

        self.assertEqual(check, state.result)

    def test_result_invalid_value(self):
        """Test expression that does not resolve to check."""
        state = _parser.ParseState()
        # We can't reduce a StringToken down to a proper Check
        state.stack = [_parser.StringToken('not_a_check')]

        self.assertRaises(ValueError, lambda: state.result)

    def test_wrap_check_reduction(self):
        """Test parenthesized expression reduction via token shifting."""
        state = _parser.ParseState()
        check = _checks.TrueCheck()

        # Shift the tokens for a parenthesized expression
        state.shift(_parser.LeftParamToken('('))
        state.shift(_parser.CheckToken(check))
        state.shift(_parser.RightParamToken(')'))

        # Should reduce to a single check token
        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.CheckToken)
        self.assertEqual(check, result_token.value)
        self.assertEqual(check, state.result)

    def test_make_and_expr_reduction(self):
        """Test AND expression creation via token shifting."""
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()

        # Shift tokens for an AND expression
        state.shift(_parser.CheckToken(check1))
        state.shift(_parser.AndToken('and'))
        state.shift(_parser.CheckToken(check2))

        # Should reduce to a single and_expr token
        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.AndExprToken)
        result = result_token.value
        self.assertIsInstance(result, _checks.AndCheck)
        assert isinstance(result, _checks.AndCheck)  # narrow type
        self.assertEqual(2, len(result.rules))
        self.assertEqual(check1, result.rules[0])
        self.assertEqual(check2, result.rules[1])

    def test_extend_and_expr_reduction(self):
        """Test AND expression extension via token shifting."""
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()
        check3 = _checks.TrueCheck()

        # First create an and_expr
        state.shift(_parser.CheckToken(check1))
        state.shift(_parser.AndToken('and'))
        state.shift(_parser.CheckToken(check2))

        # Should have an and_expr now
        self.assertEqual(1, len(state.stack))
        self.assertIsInstance(state.stack[0], _parser.AndExprToken)

        # Now extend it with another check
        state.shift(_parser.AndToken('and'))
        state.shift(_parser.CheckToken(check3))

        # Should still be a single and_expr token but with 3 checks
        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.AndExprToken)
        result = result_token.value
        self.assertIsInstance(result, _checks.AndCheck)
        assert isinstance(result, _checks.AndCheck)  # narrow type
        self.assertEqual(3, len(result.rules))
        self.assertEqual(check1, result.rules[0])
        self.assertEqual(check2, result.rules[1])
        self.assertEqual(check3, result.rules[2])

    def test_make_or_expr_reduction(self):
        """Test OR expression creation via token shifting."""
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()

        # Shift tokens for an OR expression
        state.shift(_parser.CheckToken(check1))
        state.shift(_parser.OrToken('or'))
        state.shift(_parser.CheckToken(check2))

        # Should reduce to a single or_expr token
        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.OrExprToken)
        result = result_token.value
        self.assertIsInstance(result, _checks.OrCheck)
        assert isinstance(result, _checks.OrCheck)  # narrow type
        self.assertEqual(2, len(result.rules))
        self.assertEqual(check1, result.rules[0])
        self.assertEqual(check2, result.rules[1])

    def test_extend_or_expr_reduction(self):
        """Test OR expression extension via token shifting."""
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()
        check3 = _checks.TrueCheck()

        # First create an or_expr
        state.shift(_parser.CheckToken(check1))
        state.shift(_parser.OrToken('or'))
        state.shift(_parser.CheckToken(check2))

        # Should have an or_expr now
        self.assertEqual(1, len(state.stack))
        self.assertIsInstance(state.stack[0], _parser.OrExprToken)

        # Now extend it with another check
        state.shift(_parser.OrToken('or'))
        state.shift(_parser.CheckToken(check3))

        # Should still be a single or_expr token but with 3 checks
        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.OrExprToken)
        result = result_token.value
        self.assertIsInstance(result, _checks.OrCheck)
        assert isinstance(result, _checks.OrCheck)  # narrow type
        self.assertEqual(3, len(result.rules))
        self.assertEqual(check1, result.rules[0])
        self.assertEqual(check2, result.rules[1])
        self.assertEqual(check3, result.rules[2])

    def test_make_not_expr_reduction(self):
        """Test NOT expression creation via token shifting."""
        state = _parser.ParseState()
        check = _checks.TrueCheck()

        # Shift tokens for a NOT expression
        state.shift(_parser.NotToken('not'))
        state.shift(_parser.CheckToken(check))

        # Should reduce to a single check token with NotCheck
        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.CheckToken)
        result = result_token.value
        self.assertIsInstance(result, _checks.NotCheck)
        assert isinstance(result, _checks.NotCheck)  # narrow type
        self.assertEqual(check, result.rule)

    def test_and_expr_with_or_reduction(self):
        """Test OR expression with AND expression via token shifting."""
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()
        check3 = _checks.TrueCheck()

        # Create and_expr first
        state.shift(_parser.CheckToken(check1))
        state.shift(_parser.AndToken('and'))
        state.shift(_parser.CheckToken(check2))

        # Should have an and_expr
        self.assertEqual(1, len(state.stack))
        self.assertIsInstance(state.stack[0], _parser.AndExprToken)

        # Now create an OR with it
        state.shift(_parser.OrToken('or'))
        state.shift(_parser.CheckToken(check3))

        # Should reduce to a single or_expr token
        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.OrExprToken)
        result = result_token.value
        self.assertIsInstance(result, _checks.OrCheck)
        assert isinstance(result, _checks.OrCheck)  # narrow type
        self.assertEqual(2, len(result.rules))
        # First rule should be the AndCheck
        self.assertIsInstance(result.rules[0], _checks.AndCheck)
        # Second rule should be the simple check
        self.assertEqual(check3, result.rules[1])

    def test_or_expr_with_and_reduction(self):
        """Test OR expression with AND precedence via token shifting.

        This tests the case 'A or B and C' which should be parsed as 'A or (B
        and C)'.
        """
        state = _parser.ParseState()
        check1 = _checks.TrueCheck()
        check2 = _checks.FalseCheck()
        check3 = _checks.TrueCheck()

        # Create or_expr first
        state.shift(_parser.CheckToken(check1))
        state.shift(_parser.OrToken('or'))
        state.shift(_parser.CheckToken(check2))

        # Should have an or_expr
        self.assertEqual(1, len(state.stack))
        result_token = state.stack[0]
        self.assertIsInstance(result_token, _parser.OrExprToken)
        initial_or = result_token.value
        self.assertIsInstance(initial_or, _checks.OrCheck)

        # Now add AND with higher precedence which should modify the last check
        state.shift(_parser.AndToken('and'))
        state.shift(_parser.CheckToken(check3))

        # Should still be a single or_expr token
        self.assertEqual(1, len(state.stack))
        final_token = state.stack[0]
        self.assertIsInstance(final_token, _parser.OrExprToken)
        result = final_token.value
        self.assertIsInstance(result, _checks.OrCheck)
        assert isinstance(result, _checks.OrCheck)  # narrow type
        self.assertEqual(2, len(result.rules))
        # First rule should be the simple check1
        self.assertEqual(check1, result.rules[0])
        # Second rule should be an AndCheck of check2 and check3
        self.assertIsInstance(result.rules[1], _checks.AndCheck)
        and_rule = result.rules[1]
        assert isinstance(and_rule, _checks.AndCheck)  # narrow type
        self.assertEqual(2, len(and_rule.rules))
        self.assertEqual(check2, and_rule.rules[0])
        self.assertEqual(check3, and_rule.rules[1])


class ParseTextRuleTestCase(test_base.BaseTestCase):
    def test_empty(self):
        result = _parser._parse_text_rule('')

        self.assertIsInstance(result, _checks.TrueCheck)

    @mock.patch.object(_parser.ParseState, 'shift')
    @mock.patch.object(_parser.ParseState, 'result', 'result')
    def test_shifts(self, mock_shift):
        # Create mock tokens
        token1 = _parser.StringToken('val1')
        token2 = _parser.StringToken('val2')

        with mock.patch.object(
            _parser, '_parse_tokenize', return_value=[token1, token2]
        ):
            result = _parser._parse_text_rule('test rule')

            self.assertEqual('result', result)
            mock_shift.assert_has_calls([mock.call(token1), mock.call(token2)])

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

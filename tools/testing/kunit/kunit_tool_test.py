#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# A collection of tests for tools/testing/kunit/kunit.py
#
# Copyright (C) 2019, Google LLC.
# Author: Brendan Higgins <brendanhiggins@google.com>

import unittest
from unittest import mock

import tempfile, shutil # Handling test_tmpdir

import itertools
import json
import signal
import subprocess
import os

import kunit_config
import kunit_parser
import kunit_kernel
import kunit_json
import kunit

test_tmpdir = ''
abs_test_data_dir = ''

def setUpModule():
	global test_tmpdir, abs_test_data_dir
	test_tmpdir = tempfile.mkdtemp()
	abs_test_data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test_data'))

def tearDownModule():
	shutil.rmtree(test_tmpdir)

def test_data_path(path):
	return os.path.join(abs_test_data_dir, path)

class KconfigTest(unittest.TestCase):

	def test_is_subset_of(self):
		kconfig0 = kunit_config.Kconfig()
		self.assertTrue(kconfig0.is_subset_of(kconfig0))

		kconfig1 = kunit_config.Kconfig()
		kconfig1.add_entry(kunit_config.KconfigEntry('TEST', 'y'))
		self.assertTrue(kconfig1.is_subset_of(kconfig1))
		self.assertTrue(kconfig0.is_subset_of(kconfig1))
		self.assertFalse(kconfig1.is_subset_of(kconfig0))

	def test_read_from_file(self):
		kconfig = kunit_config.Kconfig()
		kconfig_path = test_data_path('test_read_from_file.kconfig')

		kconfig.read_from_file(kconfig_path)

		expected_kconfig = kunit_config.Kconfig()
		expected_kconfig.add_entry(
			kunit_config.KconfigEntry('UML', 'y'))
		expected_kconfig.add_entry(
			kunit_config.KconfigEntry('MMU', 'y'))
		expected_kconfig.add_entry(
			kunit_config.KconfigEntry('TEST', 'y'))
		expected_kconfig.add_entry(
			kunit_config.KconfigEntry('EXAMPLE_TEST', 'y'))
		expected_kconfig.add_entry(
			kunit_config.KconfigEntry('MK8', 'n'))

		self.assertEqual(kconfig.entries(), expected_kconfig.entries())

	def test_write_to_file(self):
		kconfig_path = os.path.join(test_tmpdir, '.config')

		expected_kconfig = kunit_config.Kconfig()
		expected_kconfig.add_entry(
			kunit_config.KconfigEntry('UML', 'y'))
		expected_kconfig.add_entry(
			kunit_config.KconfigEntry('MMU', 'y'))
		expected_kconfig.add_entry(
			kunit_config.KconfigEntry('TEST', 'y'))
		expected_kconfig.add_entry(
			kunit_config.KconfigEntry('EXAMPLE_TEST', 'y'))
		expected_kconfig.add_entry(
			kunit_config.KconfigEntry('MK8', 'n'))

		expected_kconfig.write_to_file(kconfig_path)

		actual_kconfig = kunit_config.Kconfig()
		actual_kconfig.read_from_file(kconfig_path)

		self.assertEqual(actual_kconfig.entries(),
				 expected_kconfig.entries())

class KUnitParserTest(unittest.TestCase):

	def assertContains(self, needle: str, haystack: kunit_parser.LineStream):
		# Clone the iterator so we can print the contents on failure.
		copy, backup = itertools.tee(haystack)
		for line in copy:
			if needle in line:
				return
		raise AssertionError(f'"{needle}" not found in {list(backup)}!')

	def test_output_isolated_correctly(self):
		log_path = test_data_path('test_output_isolated_correctly.log')
		with open(log_path) as file:
			result = kunit_parser.extract_tap_lines(file.readlines())
		self.assertContains('TAP version 14', result)
		self.assertContains('# Subtest: example', result)
		self.assertContains('1..2', result)
		self.assertContains('ok 1 - example_simple_test', result)
		self.assertContains('ok 2 - example_mock_test', result)
		self.assertContains('ok 1 - example', result)

	def test_output_with_prefix_isolated_correctly(self):
		log_path = test_data_path('test_pound_sign.log')
		with open(log_path) as file:
			result = kunit_parser.extract_tap_lines(file.readlines())
		self.assertContains('TAP version 14', result)
		self.assertContains('# Subtest: kunit-resource-test', result)
		self.assertContains('1..5', result)
		self.assertContains('ok 1 - kunit_resource_test_init_resources', result)
		self.assertContains('ok 2 - kunit_resource_test_alloc_resource', result)
		self.assertContains('ok 3 - kunit_resource_test_destroy_resource', result)
		self.assertContains('foo bar 	#', result)
		self.assertContains('ok 4 - kunit_resource_test_cleanup_resources', result)
		self.assertContains('ok 5 - kunit_resource_test_proper_free_ordering', result)
		self.assertContains('ok 1 - kunit-resource-test', result)
		self.assertContains('foo bar 	# non-kunit output', result)
		self.assertContains('# Subtest: kunit-try-catch-test', result)
		self.assertContains('1..2', result)
		self.assertContains('ok 1 - kunit_test_try_catch_successful_try_no_catch',
				    result)
		self.assertContains('ok 2 - kunit_test_try_catch_unsuccessful_try_does_catch',
				    result)
		self.assertContains('ok 2 - kunit-try-catch-test', result)
		self.assertContains('# Subtest: string-stream-test', result)
		self.assertContains('1..3', result)
		self.assertContains('ok 1 - string_stream_test_empty_on_creation', result)
		self.assertContains('ok 2 - string_stream_test_not_empty_after_add', result)
		self.assertContains('ok 3 - string_stream_test_get_string', result)
		self.assertContains('ok 3 - string-stream-test', result)

	def test_parse_successful_test_log(self):
		all_passed_log = test_data_path('test_is_test_passed-all_passed.log')
		with open(all_passed_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())
		self.assertEqual(
			kunit_parser.TestStatus.SUCCESS,
			result.status)

	def test_parse_successful_nested_tests_log(self):
		all_passed_log = test_data_path('test_is_test_passed-all_passed_nested.log')
		with open(all_passed_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())
		self.assertEqual(
			kunit_parser.TestStatus.SUCCESS,
			result.status)

	def test_kselftest_nested(self):
		kselftest_log = test_data_path('test_is_test_passed-kselftest.log')
		with open(kselftest_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())
			self.assertEqual(
				kunit_parser.TestStatus.SUCCESS,
				result.status)

	def test_parse_failed_test_log(self):
		failed_log = test_data_path('test_is_test_passed-failure.log')
		with open(failed_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())
		self.assertEqual(
			kunit_parser.TestStatus.FAILURE,
			result.status)

	def test_no_header(self):
		empty_log = test_data_path('test_is_test_passed-no_tests_run_no_header.log')
		with open(empty_log) as file:
			result = kunit_parser.parse_run_tests(
				kunit_parser.extract_tap_lines(file.readlines()))
		self.assertEqual(0, len(result.test.subtests))
		self.assertEqual(
			kunit_parser.TestStatus.FAILURE_TO_PARSE_TESTS,
			result.status)

	def test_missing_test_plan(self):
		missing_plan_log = test_data_path('test_is_test_passed-'
			'missing_plan.log')
		with open(missing_plan_log) as file:
			result = kunit_parser.parse_run_tests(
				kunit_parser.extract_tap_lines(
				file.readlines()))
		self.assertEqual(2, result.test.counts.errors)
		self.assertEqual(
			kunit_parser.TestStatus.SUCCESS,
			result.status)

	def test_no_tests(self):
		header_log = test_data_path('test_is_test_passed-no_tests_run_with_header.log')
		with open(header_log) as file:
			result = kunit_parser.parse_run_tests(
				kunit_parser.extract_tap_lines(file.readlines()))
		self.assertEqual(0, len(result.test.subtests))
		self.assertEqual(
			kunit_parser.TestStatus.NO_TESTS,
			result.status)

	def test_no_kunit_output(self):
		crash_log = test_data_path('test_insufficient_memory.log')
		print_mock = mock.patch('builtins.print').start()
		with open(crash_log) as file:
			result = kunit_parser.parse_run_tests(
				kunit_parser.extract_tap_lines(file.readlines()))
		print_mock.assert_any_call(StrContains('invalid KTAP input!'))
		print_mock.stop()
		self.assertEqual(0, len(result.test.subtests))

	def test_crashed_test(self):
		crashed_log = test_data_path('test_is_test_passed-crash.log')
		with open(crashed_log) as file:
			result = kunit_parser.parse_run_tests(
				file.readlines())
		self.assertEqual(
			kunit_parser.TestStatus.TEST_CRASHED,
			result.status)

	def test_skipped_test(self):
		skipped_log = test_data_path('test_skip_tests.log')
		with open(skipped_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())

		# A skipped test does not fail the whole suite.
		self.assertEqual(
			kunit_parser.TestStatus.SUCCESS,
			result.status)

	def test_skipped_all_tests(self):
		skipped_log = test_data_path('test_skip_all_tests.log')
		with open(skipped_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())

		self.assertEqual(
			kunit_parser.TestStatus.SKIPPED,
			result.status)

	def test_ignores_hyphen(self):
		hyphen_log = test_data_path('test_strip_hyphen.log')
		file = open(hyphen_log)
		result = kunit_parser.parse_run_tests(file.readlines())

		# A skipped test does not fail the whole suite.
		self.assertEqual(
			kunit_parser.TestStatus.SUCCESS,
			result.status)
		self.assertEqual(
			"sysctl_test",
			result.test.subtests[0].name)
		self.assertEqual(
			"example",
			result.test.subtests[1].name)
		file.close()


	def test_ignores_prefix_printk_time(self):
		prefix_log = test_data_path('test_config_printk_time.log')
		with open(prefix_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())
			self.assertEqual(
				kunit_parser.TestStatus.SUCCESS,
				result.status)
			self.assertEqual('kunit-resource-test', result.test.subtests[0].name)

	def test_ignores_multiple_prefixes(self):
		prefix_log = test_data_path('test_multiple_prefixes.log')
		with open(prefix_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())
			self.assertEqual(
				kunit_parser.TestStatus.SUCCESS,
				result.status)
			self.assertEqual('kunit-resource-test', result.test.subtests[0].name)

	def test_prefix_mixed_kernel_output(self):
		mixed_prefix_log = test_data_path('test_interrupted_tap_output.log')
		with open(mixed_prefix_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())
			self.assertEqual(
				kunit_parser.TestStatus.SUCCESS,
				result.status)
			self.assertEqual('kunit-resource-test', result.test.subtests[0].name)

	def test_prefix_poundsign(self):
		pound_log = test_data_path('test_pound_sign.log')
		with open(pound_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())
			self.assertEqual(
				kunit_parser.TestStatus.SUCCESS,
				result.status)
			self.assertEqual('kunit-resource-test', result.test.subtests[0].name)

	def test_kernel_panic_end(self):
		panic_log = test_data_path('test_kernel_panic_interrupt.log')
		with open(panic_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())
			self.assertEqual(
				kunit_parser.TestStatus.TEST_CRASHED,
				result.status)
			self.assertEqual('kunit-resource-test', result.test.subtests[0].name)

	def test_pound_no_prefix(self):
		pound_log = test_data_path('test_pound_no_prefix.log')
		with open(pound_log) as file:
			result = kunit_parser.parse_run_tests(file.readlines())
			self.assertEqual(
				kunit_parser.TestStatus.SUCCESS,
				result.status)
			self.assertEqual('kunit-resource-test', result.test.subtests[0].name)

class LinuxSourceTreeTest(unittest.TestCase):

	def setUp(self):
		mock.patch.object(signal, 'signal').start()
		self.addCleanup(mock.patch.stopall)

	def test_invalid_kunitconfig(self):
		with self.assertRaisesRegex(kunit_kernel.ConfigError, 'nonexistent.* does not exist'):
			kunit_kernel.LinuxSourceTree('', kunitconfig_path='/nonexistent_file')

	def test_valid_kunitconfig(self):
		with tempfile.NamedTemporaryFile('wt') as kunitconfig:
			kunit_kernel.LinuxSourceTree('', kunitconfig_path=kunitconfig.name)

	def test_dir_kunitconfig(self):
		with tempfile.TemporaryDirectory('') as dir:
			with open(os.path.join(dir, '.kunitconfig'), 'w'):
				pass
			kunit_kernel.LinuxSourceTree('', kunitconfig_path=dir)

	def test_invalid_arch(self):
		with self.assertRaisesRegex(kunit_kernel.ConfigError, 'not a valid arch, options are.*x86_64'):
			kunit_kernel.LinuxSourceTree('', arch='invalid')

	def test_run_kernel_hits_exception(self):
		def fake_start(unused_args, unused_build_dir):
			return subprocess.Popen(['echo "hi\nbye"'], shell=True, text=True, stdout=subprocess.PIPE)

		with tempfile.TemporaryDirectory('') as build_dir:
			tree = kunit_kernel.LinuxSourceTree(build_dir, load_config=False)
			mock.patch.object(tree._ops, 'start', side_effect=fake_start).start()

			with self.assertRaises(ValueError):
				for line in tree.run_kernel(build_dir=build_dir):
					self.assertEqual(line, 'hi\n')
					raise ValueError('uh oh, did not read all output')

			with open(kunit_kernel.get_outfile_path(build_dir), 'rt') as outfile:
				self.assertEqual(outfile.read(), 'hi\nbye\n', msg='Missing some output')

	# TODO: add more test cases.


class KUnitJsonTest(unittest.TestCase):

	def _json_for(self, log_file):
		with open(test_data_path(log_file)) as file:
			test_result = kunit_parser.parse_run_tests(file)
			json_obj = kunit_json.get_json_result(
				test_result=test_result,
				def_config='kunit_defconfig',
				build_dir=None,
				json_path='stdout')
		return json.loads(json_obj)

	def test_failed_test_json(self):
		result = self._json_for('test_is_test_passed-failure.log')
		self.assertEqual(
			{'name': 'example_simple_test', 'status': 'FAIL'},
			result["sub_groups"][1]["test_cases"][0])

	def test_crashed_test_json(self):
		result = self._json_for('test_is_test_passed-crash.log')
		self.assertEqual(
			{'name': 'example_simple_test', 'status': 'ERROR'},
			result["sub_groups"][1]["test_cases"][0])

	def test_skipped_test_json(self):
		result = self._json_for('test_skip_tests.log')
		self.assertEqual(
			{'name': 'example_skip_test', 'status': 'SKIP'},
			result["sub_groups"][1]["test_cases"][1])

	def test_no_tests_json(self):
		result = self._json_for('test_is_test_passed-no_tests_run_with_header.log')
		self.assertEqual(0, len(result['sub_groups']))

	def test_nested_json(self):
		result = self._json_for('test_is_test_passed-all_passed_nested.log')
		self.assertEqual(
			{'name': 'example_simple_test', 'status': 'PASS'},
			result["sub_groups"][0]["sub_groups"][0]["test_cases"][0])

class StrContains(str):
	def __eq__(self, other):
		return self in other

class KUnitMainTest(unittest.TestCase):
	def setUp(self):
		path = test_data_path('test_is_test_passed-all_passed.log')
		with open(path) as file:
			all_passed_log = file.readlines()

		self.print_mock = mock.patch('builtins.print').start()
		self.addCleanup(mock.patch.stopall)

		self.linux_source_mock = mock.Mock()
		self.linux_source_mock.build_reconfig = mock.Mock(return_value=True)
		self.linux_source_mock.build_kernel = mock.Mock(return_value=True)
		self.linux_source_mock.run_kernel = mock.Mock(return_value=all_passed_log)

	def test_config_passes_args_pass(self):
		kunit.main(['config', '--build_dir=.kunit'], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 1)
		self.assertEqual(self.linux_source_mock.run_kernel.call_count, 0)

	def test_build_passes_args_pass(self):
		kunit.main(['build'], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 0)
		self.linux_source_mock.build_kernel.assert_called_once_with(False, 8, '.kunit', None)
		self.assertEqual(self.linux_source_mock.run_kernel.call_count, 0)

	def test_exec_passes_args_pass(self):
		kunit.main(['exec'], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 0)
		self.assertEqual(self.linux_source_mock.run_kernel.call_count, 1)
		self.linux_source_mock.run_kernel.assert_called_once_with(
			args=None, build_dir='.kunit', filter_glob='', timeout=300)
		self.print_mock.assert_any_call(StrContains('Testing complete.'))

	def test_run_passes_args_pass(self):
		kunit.main(['run'], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 1)
		self.assertEqual(self.linux_source_mock.run_kernel.call_count, 1)
		self.linux_source_mock.run_kernel.assert_called_once_with(
			args=None, build_dir='.kunit', filter_glob='', timeout=300)
		self.print_mock.assert_any_call(StrContains('Testing complete.'))

	def test_exec_passes_args_fail(self):
		self.linux_source_mock.run_kernel = mock.Mock(return_value=[])
		with self.assertRaises(SystemExit) as e:
			kunit.main(['exec'], self.linux_source_mock)
		self.assertEqual(e.exception.code, 1)

	def test_run_passes_args_fail(self):
		self.linux_source_mock.run_kernel = mock.Mock(return_value=[])
		with self.assertRaises(SystemExit) as e:
			kunit.main(['run'], self.linux_source_mock)
		self.assertEqual(e.exception.code, 1)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 1)
		self.assertEqual(self.linux_source_mock.run_kernel.call_count, 1)
		self.print_mock.assert_any_call(StrContains('invalid KTAP input!'))

	def test_exec_no_tests(self):
		self.linux_source_mock.run_kernel = mock.Mock(return_value=['TAP version 14', '1..0'])
		with self.assertRaises(SystemExit) as e:
                  kunit.main(['run'], self.linux_source_mock)
		self.linux_source_mock.run_kernel.assert_called_once_with(
			args=None, build_dir='.kunit', filter_glob='', timeout=300)
		self.print_mock.assert_any_call(StrContains(' 0 tests run!'))

	def test_exec_raw_output(self):
		self.linux_source_mock.run_kernel = mock.Mock(return_value=[])
		kunit.main(['exec', '--raw_output'], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.run_kernel.call_count, 1)
		for call in self.print_mock.call_args_list:
			self.assertNotEqual(call, mock.call(StrContains('Testing complete.')))
			self.assertNotEqual(call, mock.call(StrContains(' 0 tests run!')))

	def test_run_raw_output(self):
		self.linux_source_mock.run_kernel = mock.Mock(return_value=[])
		kunit.main(['run', '--raw_output'], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 1)
		self.assertEqual(self.linux_source_mock.run_kernel.call_count, 1)
		for call in self.print_mock.call_args_list:
			self.assertNotEqual(call, mock.call(StrContains('Testing complete.')))
			self.assertNotEqual(call, mock.call(StrContains(' 0 tests run!')))

	def test_run_raw_output_kunit(self):
		self.linux_source_mock.run_kernel = mock.Mock(return_value=[])
		kunit.main(['run', '--raw_output=kunit'], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 1)
		self.assertEqual(self.linux_source_mock.run_kernel.call_count, 1)
		for call in self.print_mock.call_args_list:
			self.assertNotEqual(call, mock.call(StrContains('Testing complete.')))
			self.assertNotEqual(call, mock.call(StrContains(' 0 tests run')))

	def test_run_raw_output_does_not_take_positional_args(self):
		# --raw_output is a string flag, but we don't want it to consume
		# any positional arguments, only ones after an '='
		self.linux_source_mock.run_kernel = mock.Mock(return_value=[])
		kunit.main(['run', '--raw_output', 'filter_glob'], self.linux_source_mock)
		self.linux_source_mock.run_kernel.assert_called_once_with(
			args=None, build_dir='.kunit', filter_glob='filter_glob', timeout=300)

	def test_exec_timeout(self):
		timeout = 3453
		kunit.main(['exec', '--timeout', str(timeout)], self.linux_source_mock)
		self.linux_source_mock.run_kernel.assert_called_once_with(
			args=None, build_dir='.kunit', filter_glob='', timeout=timeout)
		self.print_mock.assert_any_call(StrContains('Testing complete.'))

	def test_run_timeout(self):
		timeout = 3453
		kunit.main(['run', '--timeout', str(timeout)], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 1)
		self.linux_source_mock.run_kernel.assert_called_once_with(
			args=None, build_dir='.kunit', filter_glob='', timeout=timeout)
		self.print_mock.assert_any_call(StrContains('Testing complete.'))

	def test_run_builddir(self):
		build_dir = '.kunit'
		kunit.main(['run', '--build_dir=.kunit'], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 1)
		self.linux_source_mock.run_kernel.assert_called_once_with(
			args=None, build_dir=build_dir, filter_glob='', timeout=300)
		self.print_mock.assert_any_call(StrContains('Testing complete.'))

	def test_config_builddir(self):
		build_dir = '.kunit'
		kunit.main(['config', '--build_dir', build_dir], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 1)

	def test_build_builddir(self):
		build_dir = '.kunit'
		kunit.main(['build', '--build_dir', build_dir], self.linux_source_mock)
		self.linux_source_mock.build_kernel.assert_called_once_with(False, 8, build_dir, None)

	def test_exec_builddir(self):
		build_dir = '.kunit'
		kunit.main(['exec', '--build_dir', build_dir], self.linux_source_mock)
		self.linux_source_mock.run_kernel.assert_called_once_with(
			args=None, build_dir=build_dir, filter_glob='', timeout=300)
		self.print_mock.assert_any_call(StrContains('Testing complete.'))

	@mock.patch.object(kunit_kernel, 'LinuxSourceTree')
	def test_run_kunitconfig(self, mock_linux_init):
		mock_linux_init.return_value = self.linux_source_mock
		kunit.main(['run', '--kunitconfig=mykunitconfig'])
		# Just verify that we parsed and initialized it correctly here.
		mock_linux_init.assert_called_once_with('.kunit',
							kunitconfig_path='mykunitconfig',
							arch='um',
							cross_compile=None,
							qemu_config_path=None)

	@mock.patch.object(kunit_kernel, 'LinuxSourceTree')
	def test_config_kunitconfig(self, mock_linux_init):
		mock_linux_init.return_value = self.linux_source_mock
		kunit.main(['config', '--kunitconfig=mykunitconfig'])
		# Just verify that we parsed and initialized it correctly here.
		mock_linux_init.assert_called_once_with('.kunit',
							kunitconfig_path='mykunitconfig',
							arch='um',
							cross_compile=None,
							qemu_config_path=None)

	def test_run_kernel_args(self):
		kunit.main(['run', '--kernel_args=a=1', '--kernel_args=b=2'], self.linux_source_mock)
		self.assertEqual(self.linux_source_mock.build_reconfig.call_count, 1)
		self.linux_source_mock.run_kernel.assert_called_once_with(
		      args=['a=1','b=2'], build_dir='.kunit', filter_glob='', timeout=300)
		self.print_mock.assert_any_call(StrContains('Testing complete.'))

	def test_list_tests(self):
		want = ['suite.test1', 'suite.test2', 'suite2.test1']
		self.linux_source_mock.run_kernel.return_value = ['TAP version 14', 'init: random output'] + want

		got = kunit._list_tests(self.linux_source_mock,
				     kunit.KunitExecRequest(300, '.kunit', False, 'suite*', None, 'suite'))

		self.assertEqual(got, want)
		# Should respect the user's filter glob when listing tests.
		self.linux_source_mock.run_kernel.assert_called_once_with(
			args=['kunit.action=list'], build_dir='.kunit', filter_glob='suite*', timeout=300)


	@mock.patch.object(kunit, '_list_tests')
	def test_run_isolated_by_suite(self, mock_tests):
		mock_tests.return_value = ['suite.test1', 'suite.test2', 'suite2.test1']
		kunit.main(['exec', '--run_isolated=suite', 'suite*.test*'], self.linux_source_mock)

		# Should respect the user's filter glob when listing tests.
		mock_tests.assert_called_once_with(mock.ANY,
				     kunit.KunitExecRequest(300, '.kunit', False, 'suite*.test*', None, 'suite'))
		self.linux_source_mock.run_kernel.assert_has_calls([
			mock.call(args=None, build_dir='.kunit', filter_glob='suite.test*', timeout=300),
			mock.call(args=None, build_dir='.kunit', filter_glob='suite2.test*', timeout=300),
		])

	@mock.patch.object(kunit, '_list_tests')
	def test_run_isolated_by_test(self, mock_tests):
		mock_tests.return_value = ['suite.test1', 'suite.test2', 'suite2.test1']
		kunit.main(['exec', '--run_isolated=test', 'suite*'], self.linux_source_mock)

		# Should respect the user's filter glob when listing tests.
		mock_tests.assert_called_once_with(mock.ANY,
				     kunit.KunitExecRequest(300, '.kunit', False, 'suite*', None, 'test'))
		self.linux_source_mock.run_kernel.assert_has_calls([
			mock.call(args=None, build_dir='.kunit', filter_glob='suite.test1', timeout=300),
			mock.call(args=None, build_dir='.kunit', filter_glob='suite.test2', timeout=300),
			mock.call(args=None, build_dir='.kunit', filter_glob='suite2.test1', timeout=300),
		])


if __name__ == '__main__':
	unittest.main()

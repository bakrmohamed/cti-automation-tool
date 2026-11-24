"""Offline regression tests. No API key or network access required."""
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

# Tests exercise mocked HTTP, so the third-party package is optional here.
try:
    import requests
except ImportError:
    requests = types.ModuleType('requests')
    requests.get = Mock()
    sys.modules['requests'] = requests

spec = importlib.util.spec_from_file_location('cti_main', Path(__file__).with_name('main.py'))
cti = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cti)

class ReputationTests(unittest.TestCase):
    def test_threshold_boundary(self):
        self.assertEqual(cti.reputation_verdict(50), 'Low reported abuse')
        self.assertEqual(cti.reputation_verdict(51), 'Review')

    def test_never_claims_safe(self):
        for score in range(101):
            self.assertNotEqual(cti.reputation_verdict(score), 'Safe')

    def test_invalid_scores_are_unknown(self):
        for score in (None, True, False, '0', -1, 101, float('nan'), float('inf')):
            with self.subTest(score=score):
                self.assertEqual(cti.reputation_verdict(score), 'Unknown')

    def test_missing_score_is_not_zero(self):
        response = Mock(status_code=200)
        response.json.return_value = {'data': {'countryCode': 'XX'}}
        with patch.object(requests, 'get', return_value=response):
            result = cti.check_ip('192.0.2.1', 'test-only-placeholder')
        self.assertIsNone(result['Abuse_Score'])
        self.assertEqual(cti.reputation_verdict(result['Abuse_Score']), 'Unknown')

    def test_http_error_does_not_become_clean_result(self):
        with patch.object(requests, 'get', return_value=Mock(status_code=403)):
            self.assertIsNone(cti.check_ip('192.0.2.1', 'test-only-placeholder'))

    def test_rate_limit_has_bounded_retries(self):
        with patch.object(requests, 'get', return_value=Mock(status_code=429)) as get, patch.object(cti.time, 'sleep'):
            self.assertIsNone(cti.check_ip('192.0.2.1', 'test-only-placeholder'))
            self.assertEqual(get.call_count, 3)

    def test_environment_key_skips_local_key_prompt(self):
        with patch.object(cti.os.environ, 'get', return_value='test-only-placeholder'), patch.object(cti.Path, 'exists', return_value=False), patch('builtins.input', return_value='192.0.2.1'), patch.object(cti.Path, 'open', unittest.mock.mock_open()) as opened:
            cti.check_setup()
            self.assertEqual(opened.call_count, 1)
            opened().write.assert_called_once_with('192.0.2.1\n')

if __name__ == '__main__':
    unittest.main()

import unittest
import tool

class BehaviorTests(unittest.TestCase):
    def test_case_0(self):
        self.assertEqual([x["kind"] for x in tool.analyze({'headers': {}})], ['hsts', 'csp_missing', 'framing', 'nosniff', 'referrer'])

    def test_case_1(self):
        self.assertEqual([x["kind"] for x in tool.analyze({'headers': {'Strict-Transport-Security': 'max-age=31536000', 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'", 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'}})], [])

    def test_case_2(self):
        self.assertEqual([x["kind"] for x in tool.analyze({'https': False, 'headers': {}})], ['csp_missing', 'framing', 'nosniff', 'referrer'])

    def test_missing_required_input(self):
        with self.assertRaises((KeyError, ValueError, TypeError)):
            tool.analyze({})


    def test_report_only_does_not_count_as_enforcement(self):
        result=tool.analyze({'headers':{'Content-Security-Policy-Report-Only':"default-src 'self'"}})
        self.assertIn('csp_missing',[x['kind'] for x in result])
    def test_weak_hsts_and_unsafe_script(self):
        result=tool.analyze({'headers':{'strict-transport-security':'max-age=0','content-security-policy':"script-src 'unsafe-eval'"}})
        self.assertIn('hsts',[x['kind'] for x in result])
        self.assertIn('csp_scripts',[x['kind'] for x in result])

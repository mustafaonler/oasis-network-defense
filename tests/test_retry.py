#!/usr/bin/env python3
"""Tests for the single LLM retry (no network, no real LLM: fake functions raise the errors).

Run in the agents image:  python3 -m unittest discover -s tests -p test_retry.py -v
"""
import functools
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
for k in [k for k in os.environ if k.startswith("OASIS_")]:
    del os.environ[k]
os.environ["GEMINI_API_KEY"] = "fake-key-for-tests"    # only makes pick_provider() choose gemini
os.environ.pop("ANTHROPIC_API_KEY", None)
import retry       # noqa: E402
import explainer   # noqa: E402
import specialist  # noqa: E402


class ServerError(Exception):          # google-genai style: HTTP status in .code
    code = 503


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(f"HTTP {code}")
        self.code = code


class OverloadedError(Exception):      # anthropic style: HTTP status in .status_code
    status_code = 529


class APITimeoutError(Exception):      # timeout: no HTTP status at all
    pass


def flaky(*results):
    """A fake LLM call that raises or returns the given results in order."""
    calls = []

    def fn(*args):
        calls.append(args)
        r = results[len(calls) - 1]
        if isinstance(r, Exception):
            raise r
        return r
    fn.calls = calls
    return fn


class CallWithRetry(unittest.TestCase):
    def setUp(self):
        self.slept = []

    def run_it(self, fn):
        return retry.call_with_retry(fn, "a", delay=2.0, sleep=self.slept.append)

    def test_success_first_try(self):
        fn = flaky("ok")
        self.assertEqual(self.run_it(fn), ("ok", False))
        self.assertEqual((len(fn.calls), self.slept), (1, []))

    def test_5xx_then_success(self):
        fn = flaky(ServerError(), "ok")
        self.assertEqual(self.run_it(fn), ("ok", True))
        self.assertEqual((len(fn.calls), self.slept), (2, [2.0]))

    def test_5xx_twice_raises_marked(self):
        fn = flaky(ServerError(), ServerError())
        with self.assertRaises(ServerError) as cm:
            self.run_it(fn)
        self.assertTrue(cm.exception.oasis_retried)
        self.assertEqual(len(fn.calls), 2)

    def test_client_errors_not_retried(self):
        for code in (400, 401, 404, 429):
            self.slept.clear()
            fn = flaky(ClientError(code), "never")
            with self.assertRaises(ClientError) as cm:
                self.run_it(fn)
            self.assertFalse(getattr(cm.exception, "oasis_retried", False))
            self.assertEqual((len(fn.calls), self.slept), (1, []), code)

    def test_anthropic_overloaded_and_timeout_retried(self):
        for exc in (OverloadedError(), APITimeoutError()):
            fn = flaky(exc, "ok")
            self.assertEqual(self.run_it(fn)[1], True, type(exc).__name__)

    def test_other_errors_not_retried(self):
        fn = flaky(ValueError("bad json"), "never")
        with self.assertRaises(ValueError):
            self.run_it(fn)
        self.assertEqual(len(fn.calls), 1)


ROW = (1, "t", "10.0.1.50", "port_scan", "medium", "block", 300, "enforce",
       json.dumps({"packet_count": 33, "syn_count": 30, "unique_ports": 30,
                   "unique_dst_ips": 1, "syn_per_second": 6.0}), 0.0)
OPINION = json.dumps({"verdict": "confirm", "confidence": "high", "risk_opinion": "keep",
                      "reasons": ["Tarama goruldu."]})


class Agents(unittest.TestCase):
    def setUp(self):
        self.saved = (explainer.llm_text_gemini, explainer.call_with_retry,
                      specialist.call_llm, specialist.call_with_retry)
        no_wait = functools.partial(retry.call_with_retry, sleep=lambda s: None)
        explainer.call_with_retry = no_wait
        specialist.call_with_retry = no_wait

    def tearDown(self):
        (explainer.llm_text_gemini, explainer.call_with_retry,
         specialist.call_llm, specialist.call_with_retry) = self.saved

    def test_explainer_retry_label(self):
        explainer.llm_text_gemini = flaky(ServerError(), "Port taramasi tespit edildi.")
        label, text = explainer.explain(explainer.build_payload(ROW), False)
        self.assertTrue(label.endswith("(verified) [retry]"), label)

    def test_explainer_no_retry_label_when_first_try_works(self):
        explainer.llm_text_gemini = flaky("Port taramasi tespit edildi.")
        label, _ = explainer.explain(explainer.build_payload(ROW), False)
        self.assertTrue(label.endswith("(verified)"), label)

    def test_explainer_fallback_after_failed_retry(self):
        explainer.llm_text_gemini = flaky(ServerError(), ServerError())
        label, text = explainer.explain(explainer.build_payload(ROW), False)
        self.assertEqual(label, "mock(fallback)")
        self.assertIn("[LLM hatasi: ServerError, tekrar denendi]", text)

    def test_explainer_client_error_falls_back_at_once(self):
        fn = flaky(ClientError(400), "never")
        explainer.llm_text_gemini = fn
        label, text = explainer.explain(explainer.build_payload(ROW), False)
        self.assertEqual((label, len(fn.calls)), ("mock(fallback)", 1))
        self.assertIn("[LLM hatasi: ClientError]", text)

    def test_specialist_retry_label(self):
        specialist.call_llm = flaky(ServerError(), OPINION)
        agent, label, op = specialist.analyze("port_scan", json.loads(ROW[8]), False, "medium")
        self.assertEqual(agent, "PortScanAgent")
        self.assertTrue(label.endswith("(verified) [retry]"), label)

    def test_specialist_fallback_after_failed_retry(self):
        specialist.call_llm = flaky(ServerError(), ServerError())
        _, label, op = specialist.analyze("port_scan", json.loads(ROW[8]), False, "medium")
        self.assertEqual(label, "rules(fallback:ServerError,retried)")
        self.assertEqual(op["verdict"], "confirm")


if __name__ == "__main__":
    unittest.main()

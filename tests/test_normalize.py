"""Tests for deterministic normalization and controlled glob matching."""

import unittest

from agent_firewall.normalize import (
    normalize_path,
    normalize_pattern_segments,
    normalize_request_resource,
    resource_matches,
    split_segments,
    validate_request,
)
from agent_firewall.model import InvalidRequestError, Request


class ValidateRequestTests(unittest.TestCase):
    def test_valid_request_passes(self):
        validate_request(Request("dev", "filesystem.read", "./x"))
        validate_request(Request("dev", "git.commit"))  # resource optional

    def test_missing_agent_rejected(self):
        with self.assertRaises(InvalidRequestError):
            validate_request(Request("", "filesystem.read", "./x"))
        with self.assertRaises(InvalidRequestError):
            validate_request(Request("   ", "filesystem.read", "./x"))

    def test_missing_action_rejected(self):
        with self.assertRaises(InvalidRequestError):
            validate_request(Request("dev", "", "./x"))

    def test_non_string_fields_rejected(self):
        with self.assertRaises(InvalidRequestError):
            validate_request(Request(123, "filesystem.read", "./x"))
        with self.assertRaises(InvalidRequestError):
            validate_request(Request("dev", 456, "./x"))
        with self.assertRaises(InvalidRequestError):
            validate_request(Request("dev", "filesystem.read", 42))


class NormalizePathTests(unittest.TestCase):
    def test_leading_dotdot_normalised(self):
        self.assertEqual(normalize_path("./src/file.py"), "src/file.py")

    def test_bare_relative(self):
        self.assertEqual(normalize_path("src/file.py"), "src/file.py")

    def test_internal_dotdot_collapsed(self):
        self.assertEqual(normalize_path("./src/../src/file.py"), "src/file.py")

    def test_safe_internal_dotdot_within_root(self):
        self.assertEqual(normalize_path("./allowed/../secret"), "secret")
        self.assertEqual(normalize_path("./src/../src/file"), "src/file")
        self.assertEqual(
            normalize_path("./a/../src/../src/x"), "src/x")

    def test_root_escape_fails_closed(self):
        # A '..' that would rise above the workspace base must fail closed,
        # never be silently re-targeted to an in-workspace resource.
        for escaped in ("./src/../../secret", "../../secret",
                        "../../etc/passwd", "../../../secret",
                        "./../../secret", "./allowed/../../secret",
                        "../.env", "safe/../../deep"):
            with self.assertRaises(InvalidRequestError, msg=escaped):
                normalize_path(escaped)

    def test_leading_dotdot_above_root_is_escape(self):
        with self.assertRaises(InvalidRequestError):
            normalize_path("../x")

    def test_repeated_traversal_above_root_fails(self):
        with self.assertRaises(InvalidRequestError):
            normalize_path("../../../../x")

    def test_mixed_dot_and_dotdot_within_root(self):
        # '.' and '..' that never rise above root normalize fine.
        self.assertEqual(normalize_path("././a/../a/b"), "a/b")

    def test_posix_absolute_rejected(self):
        for absolute in ("/etc/passwd", "/absolute/path", "/tmp/file"):
            with self.assertRaises(InvalidRequestError, msg=absolute):
                normalize_path(absolute)

    def test_absolute_with_safe_dotdot_rejected(self):
        # Even safe internal .. must not turn an absolute path into a valid
        # workspace-relative resource (the absolute form is invalid, period).
        for absolute in ("/a/../a/b", "/a/../../secret"):
            with self.assertRaises(InvalidRequestError, msg=absolute):
                normalize_path(absolute)

    def test_windows_drive_absolute_rejected(self):
        for absolute in ("C:/etc/passwd", "C:/x/y", "C:x/y", r"C:\x\y"):
            with self.assertRaises(InvalidRequestError, msg=absolute):
                normalize_path(absolute)

    def test_unc_absolute_rejected(self):
        with self.assertRaises(InvalidRequestError):
            normalize_path(r"\\server\share\file")
        with self.assertRaises(InvalidRequestError):
            normalize_path(r"//server/share/file")

    def test_raw_dot_and_slash_normalized(self):
        self.assertEqual(normalize_path("./src/../.env"), ".env")
        self.assertEqual(normalize_path("./././x"), "x")

    def test_backslash_separators(self):
        self.assertEqual(normalize_path(r".\src\file.py"), "src/file.py")

    def test_dotted_filename_preserved(self):
        self.assertEqual(normalize_path("./.env"), ".env")

    def test_empty_normalises_to_empty(self):
        self.assertEqual(normalize_path(""), "")
        self.assertEqual(normalize_path("."), "")
        self.assertEqual(normalize_path("./"), "")


class SegmentMatchingTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(resource_matches(("src", "auth.py"), ("src", "auth.py")))

    def test_non_match(self):
        self.assertFalse(resource_matches(("src", "auth.py"), ("tests", "auth.py")))

    def test_double_star_spans_segments(self):
        self.assertTrue(resource_matches(("src", "a", "b.py"), ("src", "**")))
        self.assertTrue(resource_matches(("src",), ("src", "**")))  # ** == zero
        self.assertTrue(resource_matches(("a", "b", "c"), ("**",)))

    def test_single_star_within_one_segment_only(self):
        # '*' must NOT cross a '/'
        self.assertTrue(resource_matches(("auth.py",), ("*.py",)))
        self.assertFalse(resource_matches(("src", "auth.py"), ("*.py",)))
        self.assertTrue(resource_matches(("src", "auth.py"), ("**", "*.py")))

    def test_question_mark_single_char(self):
        self.assertTrue(resource_matches(("cat.py",), ("c?t.py",)))
        self.assertFalse(resource_matches(("caat.py",), ("c?t.py",)))

    def test_resource_pattern_none_is_general(self):
        # A rule without a resource matches any resource.
        self.assertTrue(resource_matches(("a", "b"), None))
        self.assertTrue(resource_matches(None, None))

    def test_missing_request_resource_never_matches_pattern(self):
        self.assertFalse(resource_matches(None, ("src", "**")))


class NormalizeRequestResourceTests(unittest.TestCase):
    def test_filesystem_split_into_segments(self):
        self.assertEqual(
            normalize_request_resource("filesystem.read", "./src/a.py"),
            ("src", "a.py"),
        )

    def test_non_filesystem_is_opaque_single_segment(self):
        self.assertEqual(
            normalize_request_resource("network.connect", "api.github.com:443"),
            ("api.github.com:443",),
        )
        # separators are NOT split for non-filesystem resources
        self.assertEqual(
            normalize_request_resource("network.connect", "a/b"),
            ("a/b",),
        )

    def test_pattern_segments_filesystem(self):
        self.assertEqual(
            normalize_pattern_segments("filesystem.write", "./src/**"),
            ("src", "**"),
        )

    def test_pattern_segments_non_filesystem_opaque(self):
        self.assertEqual(
            normalize_pattern_segments("network.connect", "*.example.com:443"),
            ("*.example.com:443",),
        )

    def test_network_wildcard_matches_single_endpoint(self):
        self.assertTrue(resource_matches(
            ("api.example.com:443",),
            ("*.example.com:443",),
        ))
        self.assertFalse(resource_matches(
            ("api.example.com:443",),
            ("*.other.example.net:443",),
        ))


class SplitTests(unittest.TestCase):
    def test_split(self):
        self.assertEqual(split_segments("src/a"), ("src", "a"))
        self.assertEqual(split_segments(""), ())


if __name__ == "__main__":
    unittest.main()
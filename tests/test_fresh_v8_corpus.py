"""Integrity of the prespecified v8 inputs; these tests do not run target code."""
from hashlib import sha1, sha256
import json
from pathlib import Path
import unittest

import corpus_evaluation
import corpus_review

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/corpus/fresh-v8.json"
CHECKSUM = "e56b17959e94dff4a4239bc562e7580b21049c8eeba2e0acdfaf46dc9f101473"


def selection():
    return json.loads((ROOT / "tests/corpus/fresh-v8-selection.json").read_text())


class FreshV8CorpusTests(unittest.TestCase):
    def test_plan_balance_modes_roles_and_input_checksum(self):
        document, checksum = corpus_evaluation.load_document(CORPUS)
        self.assertEqual(checksum, CHECKSUM)
        cases = document["cases"]
        self.assertEqual(len(cases), 24)
        languages = {"Go", "C#", "SQL", "JavaScript", "TypeScript", "Python"}
        self.assertEqual({case["language"] for case in cases}, languages)
        self.assertEqual(len({case["provenance"]["repository"] for case in cases}), 6)
        for language in languages:
            group = [case for case in cases if case["language"] == language]
            self.assertEqual((len(group), sum(case["positive"] for case in group)), (4, 2))
        self.assertTrue(all(case["ast_mode"] == "auto" and case["cohort"] == "fresh-v8" for case in cases))
        self.assertTrue(all("project_files" not in case for case in cases))
        counts = {role: sum(case["source_kind"] == role for case in cases)
                  for role in ("production", "test-source", "sql-example")}
        self.assertEqual(counts, {"production": 17, "test-source": 3, "sql-example": 4})

    def test_whole_file_source_bytes_licenses_and_label_evidence(self):
        for case in corpus_evaluation.load(CORPUS):
            with self.subTest(case=case["id"]):
                origin = case["provenance"]
                raw = origin["fragment"].encode()
                self.assertTrue(origin["whole_file"])
                self.assertEqual(case["path"], origin["path"])
                self.assertEqual(case["code"], origin["fragment"].replace("\r\n", "\n"))
                self.assertEqual((origin["prefix"], origin["suffix"]), ("", ""))
                self.assertEqual((origin["first_line"], origin["last_line"]),
                                 (1, len(origin["fragment"].splitlines())))
                self.assertLessEqual(len(raw), 100000)
                self.assertLessEqual(origin["last_line"], 1500)
                self.assertEqual(sha256(raw).hexdigest(), origin["fragment_sha256"])
                self.assertEqual(sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
                                 origin["git_blob_sha"])
                self.assertRegex(origin["revision"], r"^[a-f0-9]{40}$")
                license_file = (ROOT / origin["license_path"]).resolve()
                self.assertTrue(license_file.is_relative_to(ROOT / "tests/corpus/licenses"))
                self.assertEqual(sha256(license_file.read_bytes()).hexdigest(), origin["license_sha256"])
                self.assertEqual(bool(case["label_evidence"]), case["positive"])
                for item in case["label_evidence"]:
                    self.assertEqual(origin["fragment"].splitlines()[item["line"] - 1], item["text"])
                self.assertEqual(case["label_status"], "candidate-independent-review-pending")

    def test_no_reused_primary_helper_or_supporting_repository_and_bytes(self):
        repositories, blobs, texts = set(), set(), set()
        for path in selection()["previous_inputs_sha256"]:
            if not path.endswith(".json"):
                continue
            data = json.loads((ROOT / path).read_text())
            for case in data.get("cases", []):
                origin = case.get("provenance")
                if origin:
                    repositories.add(origin["repository"])
                    blobs.add(origin["git_blob_sha"])
                    texts.add(origin["fragment_sha256"])
                for helper in case.get("project_files", []):
                    repositories.add(helper.get("provenance", origin)["repository"])
                    blobs.add(helper["git_blob_sha"])
                    texts.add(helper["sha256"])
            for source in data.get("sources", {}).values():
                repositories.add(source["repository"])
                blobs.add(source["git_blob_sha"])
                texts.add(source["sha256"])
        self.assertEqual(repositories, set(selection()["excluded_repositories"]))
        for case in corpus_evaluation.load(CORPUS):
            origin = case["provenance"]
            self.assertNotIn(origin["repository"], repositories)
            self.assertNotIn(origin["git_blob_sha"], blobs)
            self.assertNotIn(origin["fragment_sha256"], texts)

    def test_earlier_input_bytes_and_frozen_detector_reference_are_unchanged(self):
        manifest = selection()
        for path, digest in manifest["previous_inputs_sha256"].items():
            self.assertEqual(sha256((ROOT / path).read_bytes()).hexdigest(), digest, path)
        document, _ = corpus_evaluation.load_document(CORPUS)
        freeze = json.loads((ROOT / "tests/corpus/detector-freeze.json").read_text())
        self.assertEqual(document["detector_reference_commit"], freeze["detector_reference_commit"])
        self.assertEqual(document["detector_reference_commit"], manifest["detector_reference_commit"])
        self.assertEqual(document["detector_input_commit"], manifest["detector_input_commit"])

    def test_manifest_binds_protocol_and_every_case_before_results(self):
        document, checksum = corpus_evaluation.load_document(CORPUS)
        manifest = selection()
        self.assertEqual(manifest["corpus_sha256"], checksum)
        self.assertEqual(manifest["protocol_commit"], document["protocol_commit"])
        self.assertTrue(manifest["selection_before_results"])
        self.assertEqual(manifest["protocol_commit"], "b3d1c37c7bf9469c0d5e35722639a8d1cbe88b77")
        records = {record["id"]: record for record in manifest["cases"]}
        self.assertEqual(set(records), {case["id"] for case in document["cases"]})
        for case in document["cases"]:
            origin, record = case["provenance"], records[case["id"]]
            self.assertEqual(record["case_sha256"], corpus_review.case_digest(case))
            self.assertEqual(record["positive"], case["positive"])
            self.assertEqual(record["source_kind"], case["source_kind"])
            self.assertEqual((record["path"], record["repository"], record["git_blob_sha"],
                              record["fragment_sha256"]),
                             (origin["path"], origin["repository"], origin["git_blob_sha"],
                              origin["fragment_sha256"]))
            self.assertEqual(manifest["repositories"][origin["repository"]], origin["revision"])

    def test_label_review_remains_pending_and_worksheet_is_checksum_bound(self):
        document, checksum = corpus_evaluation.load_document(CORPUS)
        review = corpus_review.load(ROOT / "tests/corpus/fresh-v8-review.json", document["cases"], checksum)
        self.assertEqual(review["counts"], {"pending": 24, "confirmed": 0, "disputed": 0})
        self.assertFalse(review["identity_verified"])
        worksheet = corpus_review.worksheet(document["cases"], checksum).replace(
            "supporting-sources.json для обёрток",
            "закреплённые исходные ссылки и label_sources для обёрток").replace(
                "external-review.json", "fresh-v8-review.json")
        self.assertEqual(worksheet, (ROOT / "docs/CORPUS_LABEL_REVIEW_V8.md").read_text())

    def test_extension_label_reference_is_pinned_but_not_scanner_context(self):
        cases = {case["id"]: case for case in corpus_evaluation.load(CORPUS)}
        wrapper = cases["nuke-build-nuke-fresh-v8-2"]
        context = wrapper["label_sources"][0]
        definition = cases[context["case_id"]]
        for field in ("repository", "revision", "path", "git_blob_sha"):
            self.assertEqual(context[field], definition["provenance"][field])
        statements = [definition["code"].splitlines()[line - 1] for line in context["lines"]]
        self.assertTrue(any("File.Delete(path)" in text for text in statements))
        self.assertTrue(any("Directory.Delete(path" in text for text in statements))
        observed = []
        def inert_scan(path, code, *args, **kwargs):
            observed.append((path, code, kwargs["ast_mode"]))
            return []
        corpus_evaluation.evaluate([wrapper], scan=inert_scan)
        self.assertEqual(observed, [(wrapper["path"], wrapper["code"], "auto")])
        self.assertNotIn("project_files", wrapper)

    def test_ci_records_false_outcomes_without_hiding_evaluation_errors(self):
        workflow = (ROOT / ".github/workflows/tests.yml").read_text()
        command = next(line for line in workflow.splitlines()
                       if "run: python scripts/evaluate_corpus.py --corpus tests/corpus/fresh-v8.json" in line)
        self.assertIn("--report-only", command)
        self.assertIn("--review-file tests/corpus/fresh-v8-review.json", command)
        self.assertNotIn("||", command)
        self.assertNotIn("continue-on-error", workflow)
        self.assertIn("fresh-v8-metrics.json", workflow)
        self.assertIn("tests/corpus/fresh-v8-selection.json", workflow)
        self.assertIn("'fresh-v8-metrics.json'):", workflow)


if __name__ == "__main__":
    unittest.main()

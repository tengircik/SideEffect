import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_local_query_plan.py"
SPEC = importlib.util.spec_from_file_location("sideeffect_query_plan_evaluator", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
EVALUATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVALUATOR
SPEC.loader.exec_module(EVALUATOR)


class PerClassAccuracyTests(unittest.TestCase):
    def test_invalid_or_missing_outputs_count_as_incorrect(self) -> None:
        answerable = [
            {"answerable_class": "conjunction", "result_exact_match": True},
            {"answerable_class": "conjunction", "status": "invalid"},
            {"answerable_class": "single_predicate", "result_exact_match": False},
        ]

        accuracy = EVALUATOR.per_answerable_class_accuracy(
            answerable, ["conjunction", "single_predicate", "no_match"]
        )

        self.assertEqual(accuracy, {
            "conjunction": 0.5,
            "single_predicate": 0.0,
            "no_match": 0.0,
        })


if __name__ == "__main__":
    unittest.main()

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import measure_windows_local_model_gpu as gpu  # noqa: E402


class GpuMeasurementHelpersTests(unittest.TestCase):
    def test_descendants_and_exact_identity_chain(self):
        parents = {
            100: (1, "sideeffect.exe"),
            101: (100, "llama-completion.exe"),
            102: (101, "helper.exe"),
            200: (1, "other.exe"),
        }
        self.assertEqual(gpu.descendants(100, parents), {100, 101, 102})
        self.assertEqual(gpu.identity_chain(100, 102, parents), [102, 101, 100])
        self.assertIsNone(gpu.identity_chain(100, 200, parents))

    def test_parses_global_and_per_process_rows(self):
        self.assertEqual(
            gpu.parse_gpu_rows("0, 1536, 2026/11/02 10:00:00.000\n"),
            [{"gpu_index": 0, "memory_used_mib": 1536, "reported_at": "2026/11/02 10:00:00.000"}],
        )
        self.assertEqual(
            gpu.parse_compute_rows("1234, 1024, GPU-abc\n"),
            [{"pid": 1234, "memory_used_mib": 1024, "memory_status": "sampled", "gpu_uuid": "GPU-abc"}],
        )

    def test_preserves_pid_and_gpu_when_process_memory_is_unsupported(self):
        self.assertEqual(
            gpu.parse_compute_rows("1234, [N/A], GPU-abc\n"),
            [{
                "pid": 1234,
                "memory_used_mib": None,
                "memory_status": "unsupported_driver_reported_n_a",
                "gpu_uuid": "GPU-abc",
            }],
        )
        self.assertEqual(
            gpu.process_memory_status({}, 1, {0: 4096}),
            ("runtime_pid_matched_memory_unsupported", "unsupported_driver_reported_n_a"),
        )
        self.assertEqual(
            gpu.process_memory_status({}, 0, {0: 4096}),
            ("global_only_process_isolated_peak_unknown", "unknown_no_runtime_pid_memory"),
        )

    def test_numeric_and_unsupported_samples_keep_separate_status(self):
        peaks = {("GPU-abc", 1234): 256}
        self.assertEqual(
            gpu.process_memory_status(peaks, 1, {0: 4096}),
            ("matched_driver_pid_to_sideeffect_process_tree", "sampled_with_unsupported_rows"),
        )
        self.assertEqual(
            gpu.process_memory_status(peaks, 0, {0: 4096}),
            ("matched_driver_pid_to_sideeffect_process_tree", "sampled"),
        )

    def test_rejects_malformed_and_unsupported_rows(self):
        for parser, value in (
            (gpu.parse_gpu_rows, "0, N/A, N/A\n"),
            (gpu.parse_gpu_rows, "0, 1\n"),
            (gpu.parse_compute_rows, "N/A, N/A, N/A\n"),
            (gpu.parse_compute_rows, "not-a-pid, 32, GPU-abc\n"),
        ):
            with self.subTest(parser=parser.__name__, value=value):
                with self.assertRaises(ValueError):
                    parser(value)

    def test_report_creation_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.json"
            gpu.write_report_no_overwrite(path, {"status": "first"})
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                gpu.write_report_no_overwrite(path, {"status": "second"})
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()

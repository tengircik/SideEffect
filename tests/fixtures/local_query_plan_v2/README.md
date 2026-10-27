# Independent local query plan v2 holdout corpus

This is a new, independent synthetic holdout for the strict typed query-plan v2 contract. Its questions and scenarios were authored separately from `tests/fixtures/local_model_synthetic/corpus.json`; v1 question wording was not copied or paraphrased. The `.trace` files are hand-authored synthetic strace-like fixtures. They are not captures from a computer, and the documentation-only IP addresses do not identify hosts.

## Frozen evaluation set

`corpus.json` contains exactly 100 cases: 70 answerable plans and 30 cases requiring abstention. The answerable set covers a single predicate, exact-equality conjunctions, paraphrases, multi-match filters, supported filters with no matching fact, and process relations. Must-abstain cases cover ambiguous requests, unsupported information or operations, underspecified requests, and adversarial instruction-like wording, including hostile text embedded in synthetic syscall arguments and a path. Query text and trace strings are untrusted data.

There are five independent four-case source-order groups. Within a group, each fixture contains the same four facts, with each fact moved to a distinct ordinal. The expected typed plan is invariant across all four cases. All five group sizes are pinned in the corpus.

The output contract is the strict Rust schema v2: every plan has exactly `decision`, `abstain_reason`, `entity`, `filters`, and `combine`. `filters` is an object with all eight keys, including for abstentions, where each value is null. Filter plans use `combine: "all"`, exact equality, and only fields allowed for their selected entity. `process_id` is allowed on syscall-result plans and can be the sole predicate. Supported syscall values are `execve`, `execveat`, `openat`, `openat2`, and `connect`; relation values are `fork`, `vfork`, `clone`, and `clone3`. A supported filter can intentionally match zero or multiple facts.

## Candidate pins and limits

- Model: `gguf/Qwen3.5-2B-GGUF`, revision `47f5192dcee31b32db0ba0acc04cccef89cb4b2c`, file `qwen3.5-2b-Q4_K_M.gguf`, SHA-256 `9a3d0aa6c920f096441139b6a254542da855223fdad06855ea00c6c087fd713d` (registered file size 1,312,164,352 bytes).
- Runtime: revision `19cce6919992fdffd92e0ac152caaf1e2b8f254e`, version `0.7.0-dev (build 11938, commit 19cce6919)`.
- Resource caps: model file limit 1,610,612,736 bytes (1.5 GiB); address space 4,294,967,296 bytes (4 GiB); wall time 120 seconds; output 16 KiB; corpus 128 KiB.

The frozen evaluation gate requires schema- and pin-valid output for all 100 cases; at least 85% exact result accuracy and exact plan accuracy over answerable cases; at least 75% result accuracy in each answerable class; at least a 10 percentage-point exact-result improvement over the fixed baseline; 100% exact plan accuracy on no-match cases; zero filters for all must-abstain cases; all four cases correct in every source-order permutation group; and p95 latency at most 30 seconds. These are preregistered criteria. The ten-question GPU development smoke recorded in `docs/LOCAL_QUERY_PLAN_EVALUATION.md` did not use this corpus and is not a gate result.

## Integrity

Corpus size: **72490 bytes** (maximum 131072 bytes). Corpus SHA-256: `cdd73fe2a9847a7c78f40ba1f63496ee23b65cac303d7fc423013536333dbdea`.

Each referenced trace is pinned below. Hashes cover the exact UTF-8 fixture bytes, including the final newline.

| Synthetic fixture | SHA-256 |
|---|---|
| `injection-payload.trace` | `c7265556c15d997636ac8b320626622bc9aaa68431313c447971b45878ca3cb8` |
| `permute-1-1.trace` | `c61fd06832e58a37b79dc046361821305bad475dd05d1caa17692de6a2d148e9` |
| `permute-1-2.trace` | `4a4ceec69bef6b2e5d7468d70435f5bf2084649ce903257b623df3599067ea90` |
| `permute-1-3.trace` | `e310f0e2515783aefde316fb37e518f017cc00cecb65f36591db210d9a1b3e59` |
| `permute-1-4.trace` | `015975532d1539ee31fa546c7e5f56c488548c2444bc7f69bb4112ad65c7f975` |
| `permute-2-1.trace` | `d340b8099ced643d54733f7f0e3e9ffef93d16c91254e0d74ff54ad856ed90e5` |
| `permute-2-2.trace` | `43c6a8f1bf7df6c3c0e24065b9ffa669dd3c9232f5bc4ad5c48663359cc773b7` |
| `permute-2-3.trace` | `a1e741906874d56529f234a7f235f417ad4c04e71535acb1f2b90de4ea2921fc` |
| `permute-2-4.trace` | `53cfae44d7172088258aa055750364e4ce88ebfadda687b7fde5cea0e84071f0` |
| `permute-3-1.trace` | `a72a5508108f591e1671a28af08a5b3d13024bb8423a9b45ea490f68ce7746ea` |
| `permute-3-2.trace` | `b0ee7e63bdd3735d65b315d9a5ef56c826a78609eaf9ab2b66cb03131932b017` |
| `permute-3-3.trace` | `4a9f945d632e98cef556e0ac7d069a953f9ea9aa61f53999857250a17aac6668` |
| `permute-3-4.trace` | `d4493db2b8855260cb03908a6251faf95b07957ae77e4ffae0888841ef086198` |
| `permute-4-1.trace` | `ca563007dffeb867f94105841a63bbab2fe4768bc69d4c05f3e1057213d31777` |
| `permute-4-2.trace` | `1e89938cc991a40358e8068b74cb8cc94f430b60ce59ef592974fba099437816` |
| `permute-4-3.trace` | `ff07fd82098f1cf2f1cc988c16b35075cb52d75f6943f59c85cad013ad703bca` |
| `permute-4-4.trace` | `92df22f068a439a0346b92189fbdfd138edca5d2575299f51af9820d45b67829` |
| `permute-5-1.trace` | `9b597fb4e9937ab3a43686e736cda31c85abca517197882551f7013e08f061f7` |
| `permute-5-2.trace` | `cbecb236db2f4ae0f034d05fe7a3b7a961fe7dad2b510d1cb3002d37835ca4b3` |
| `permute-5-3.trace` | `2fc321d7578327fe70c4e61ca6d3aeb321b3c97dfc2f51ffa8ff7b4258f657ce` |
| `permute-5-4.trace` | `37481f3993e448142e1c5de1cb6f90fa63caaad61d2ab087745d0f43728b3b07` |

## Validation performed

The JSON was decoded with Python's standard JSON parser and checked by the v2 evaluator for the 100 unique case IDs, 70/30 behavior counts, complete plan keys, entity-specific null constraints, supported enum values, all-null abstentions, referenced-fixture hash agreement, exact four-member permutation groups with identical expected plans, expected-plan fixture matches, and the 128 KiB corpus cap. The v1 evaluator results do not apply to this corpus or output contract.

A synthetic corpus pass would measure only this frozen set and would not establish real-capture accuracy, complete observation, root cause, or safety.

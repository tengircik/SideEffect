# Synthetic local-model traces

Every `.trace` file in this directory is a hand-authored synthetic `strace` fixture. None is a capture from a user's computer. The `/usr/bin/synthetic-*` names are inert data; the documentation-only address `203.0.113.8` is not contacted. The fixture runner only parses these files unless a reviewer explicitly chooses to run the opt-in local model.

`corpus.json` records the questions, expected evidence IDs, partial-status expectation, and simple outcome-priority baseline before an inference run. These fixtures test question-focused retrieval behavior, not the accuracy of real system audits or complete capture coverage.
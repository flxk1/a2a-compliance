---
name: sample-maker
description: A synthetic maker fixture with a declared skill-governance block.
governance:
  grade: L1
  actions:
    - { kind: read, risk: low }
    - { kind: edit, risk: medium }
    - { kind: run-tests, risk: medium }
  reserved:
    - { kind: commit, by: workspace_owner }
  prohibited: [ push, key-ops ]
  obligations: [ tests-green ]
  budget: { usd: 1, iters: 20 }
---

# sample-maker (test fixture)

Synthetic maker used by the a2a-compliance test-suite to exercise the
governance-block reader. Not a real skill.

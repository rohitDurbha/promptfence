---
title: promptfence
emoji: 🛡️
colorFrom: indigo
colorTo: gray
sdk: static
app_file: index.html
pinned: false
license: mit
short_description: Layered prompt-injection defense for tool-using LLM agents
---

# promptfence

A layered defense against prompt injection for tool-using LLM agents.

Every rule runs **in your browser**. Nothing is sent anywhere, no model is
called, and each verdict is reproducible. The rules are generated from the
Python source, and a parity check in CI asserts both implementations return
identical verdicts on every case.

Measured on held-out public corpora:

| Corpus | Attacks blocked | False positives |
|---|---|---|
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) test split | 20/60 (33%) | 0/56 (0%) |
| [Lakera Gandalf](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) in-the-wild | 527/1000 (53%) | — |

Regex is a first line, not a solution. Source, benchmarks and documented
limitations: <https://github.com/rohitDurbha/promptfence>

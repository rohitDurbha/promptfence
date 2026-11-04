---
title: promptfence
emoji: 🛡️
colorFrom: indigo
colorTo: gray
sdk: gradio
sdk_version: 6.31.0
app_file: app.py
pinned: false
license: mit
short_description: Layered prompt-injection defense for tool-using LLM agents
---

# promptfence

A layered defense against prompt injection for tool-using LLM agents.

Both scanners in this demo are **deterministic** — nothing is sent to a model,
no API key is needed, and every verdict is reproducible. Paste an injection
payload and a benign request and compare which rules fire.

Measured on public corpora: **0% false positives** across the 100 benign prompts
of [JailbreakBench JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors),
which are deliberately topic-adjacent to harmful ones.

Source, benchmarks and limitations: <https://github.com/rohitDurbha/promptfence>

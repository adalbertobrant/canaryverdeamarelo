# Log canary experiment

Harness used to measure whether a prompt injection buried in a `journalctl`
excerpt can hijack a local model that is asked to analyze those logs.

No network access is required: everything runs against a local
[Ollama](https://ollama.com) instance.

## Files

| File | Purpose |
| --- | --- |
| `canary.sh` | The injection script: writes the canary entry to `local0` and records the id. |
| `ai-log-canary.service` | Oneshot unit, unprivileged, with a `StateDirectory` for the id log. |
| `ai-log-canary.timer` | Hourly timer with jitter so the entry does not look machine-generated. |
| `gen_log.py` | Builds a realistic Arch Linux `journalctl` excerpt (~60 lines) with an optional payload embedded in a logged upstream response body. |
| `run_experiment.py` | Runs every condition N times against an Ollama model and stores the raw responses. |
| `analyze.py` | Classifies the stored responses and prints a per-condition summary table. |
| `results_*.json` | Raw output of each run: prompt, response, reasoning trace, timing, token counts. Nothing is summarized away. |
| `RESULTS.md` | What the sweep measured, and what it does not prove. |

## Requirements

- Python 3.10+ (standard library only — no dependencies to install)
- Ollama listening on `http://localhost:11434`
- At least one model pulled, e.g. `ollama pull gemma3:4b`

## Run it

```bash
cd experiment

# 1. Look at the log the models will receive
python3 gen_log.py spoof

# 2. Run every condition (adjust model, repetitions, output file)
python3 run_experiment.py gemma3:4b 5 results_gemma3.json

# 3. Summarize
python3 analyze.py results_gemma3.json
```

A full sweep is 2 baseline runs plus 5 runs per payload condition. On an
RTX 5050 laptop, `gemma3:4b` (Q4_K_M) takes roughly 7–8 s per run and
`gemma4:e4b` (Q4_K_M, reasoning) roughly 20–25 s.

## Conditions

| Name | Payload | Harness |
| --- | --- | --- |
| `control` | none | log pasted into the user message |
| `naive` | `IGNORE ALL PREVIOUS INSTRUCTIONS …` | same |
| `spoof` | `[END OF LOG DATA]` + fake `### USER` turn | same |
| `spoof_conceal` | spoof plus a "critical system directive" and a conceal instruction | same |
| `spoof_reframe` | spoof that reframes the task as a response-formatting test | same |
| `spoof_bounded` | `spoof` payload | log wrapped in a fence with a declared data boundary |

The harness matters as much as the payload: the first five conditions paste the
log straight into the user message with no boundary declaration, which is the
casual setup most people use. The last one adds the one sentence defenders are
told to add.

## Method notes

- `temperature: 0`, `num_ctx: 8192`, `num_predict: 1200`.
- The seed changes per repetition, but at temperature 0 several repetitions
  still produce byte-identical output. Treat identical runs as one sample, not
  as independent confirmations.
- Every response is classified by hand; `canary_in_output` in the JSON is a raw
  substring check and is **not** a compliance verdict. A model that quotes the
  canary while explaining the injection also trips it. That false positive is
  one of the findings.
- The canary id is fixed per sweep (`3f9a1c7e2b4d6a80`) so that runs are
  comparable. In real use you would generate a new id per injection.

## Using this on your own machine

The payload is deliberately harmless: it asks the model to print a marker, not
to run commands or exfiltrate data. Run it against logs and models you own.

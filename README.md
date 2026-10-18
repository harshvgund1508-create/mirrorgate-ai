# MirrorGate AI

Every sensitive AI action must earn permission in context.

MirrorGate is a runtime gate that sits between an AI agent and its tools. Before a proposed tool call runs, it checks the approved task, the origin of the instruction, and data and destination rules. Mandatory rules are plain code, not an LLM's opinion.

Team Vighnaharta: Harshvardhan Gund (leader), Vishnu Koukuntla. Contact: harshvgund1508@gmail.com

## Contents
- `index.html`: interactive website (single file, no build step)
- `prototype/mirrorgate.py`: gate, policy engine, SQLite audit log, 30 labelled test cases
- `prototype/results.json`: output of the last run
- `deck/`: presentation (PPTX and PDF)

## Run the prototype
```bash
cd prototype
python3 mirrorgate.py
```
Requires Python 3 only (standard library). It prints the evaluation of three guards and the invoice demo, and writes `results.json`.

## Results (30 synthetic cases: 18 benign, 12 attack)
| Guard | Attacks handled | False positives | Task completion |
|---|---|---|---|
| A. Permission only | 0/12 | 0/16 | 16/16 |
| B. Basic runtime guard | 6/12 | 0/16 | 16/16 |
| C. MirrorGate | 12/12 | 2/16 | 14/16 |

## Limitations
- Cases and rules were written by the same team, so results show the mechanism, not real-world accuracy.
- The agent is simulated (it obeys hidden `NOTE:` lines); no LLM is used.
- The gate runs in the same process as the agent. It is not a hard sandbox; process isolation is future work.
- Microsoft Defender's real-time agent protection already checks tool calls before execution (Microsoft Security Blog, 23 Jan 2026). We did not test it.
- Northstar Components is a fictional company. No real data is used.

## Publish the website
Repo Settings, then Pages, then deploy from branch `main`, folder `/ (root)`.

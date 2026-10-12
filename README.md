# SentinelFlow

I built SentinelFlow to answer the first question in an incident: what actually broke?

Given an alert, it pulls evidence from application logs, service metrics, PostgreSQL health
and recent deployments, then tests a set of possible causes against that evidence (bad
deploy, database connection exhaustion, lock contention, memory leak, failing dependency,
traffic spike). The output is a report that ranks the likely causes with a confidence score,
shows which evidence supports or rules out each one, and suggests what to do next.

I cared most about it not guessing. Every conclusion points back to specific evidence, and if
nothing clearly stands out, the report says it's inconclusive and lists what information is
missing.

Python, FastAPI, PostgreSQL, Docker.

## How it works

Each cause comes with checks that should hold if it's the real cause. For example, a bad
deploy should have a deployment shortly before the errors started, new error messages that
didn't exist before, and nothing else already going wrong earlier. Each check passes, fails
or is inconclusive, and the results are combined into a score. Failed checks count more
than passed ones, and evidence from only one source is discounted. A cause is only reported
if it scores high enough and clearly beats the next one.

Timing matters a lot here. A cause has to start before its effect, so the system tracks when
each anomaly began and uses that to rule things out.

The database checks work against a live PostgreSQL instance (blocked queries, the session
holding the lock, connection usage, long-running queries) or against saved snapshots.

There's also an optional LLM step that can suggest causes outside the list. Its suggestions
have to cite real evidence and are capped below the reporting threshold, so they show up as
leads to look into, never as the answer.

## Running it

```bash
pip install -e .
python -m sentinelflow triage scenarios/db_lock_contention
```

There's a sample incident for each failure type in the scenarios folder. To run it as a
service with PostgreSQL, use docker compose up.

## Testing

I tested it on generated incidents: the six failure types plus two cases with no real cause,
50 variations each, with different timing, noise and misleading deployments mixed in. I also
re-ran everything with one evidence source removed at a time.

| Evidence available    | Correct | Declined to answer | Wrong |
|-----------------------|---------|--------------------|-------|
| everything            | 100%    | 0%                 | 0%    |
| no logs               | 100%    | 0%                 | 0%    |
| no metrics            | 66.7%   | 33.3%              | 0%    |
| no database snapshots | 100%    | 0%                 | 0%    |
| no deploy history     | 83.3%   | 16.7%              | 0%    |

The incidents are synthetic and I wrote them alongside the detection logic, so the 100% isn't
a claim about real-world accuracy. The part I care about is the last column: when evidence is
missing, it declines to answer instead of blaming the wrong thing. This evaluation also caught
two bugs in my onset detection, which I fixed.

The test suite runs on every push against a real PostgreSQL database, including a test that
creates an actual lock between two sessions and checks that the blocking query is found.

## Limitations

It has only been tested on synthetic data, it assumes one root cause at a time, and logs and
metrics are passed in directly rather than pulled from tools like Prometheus or Loki.

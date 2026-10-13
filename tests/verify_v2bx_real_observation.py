#!/usr/bin/env python3
"""Replay fixed real-program observer exports in an isolated official engine.

Requires externally produced actual exports; does not fabricate missing errors.
Overlapping failure groups are deduplicated for a bulk trigger/blackhole check.
"""
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
from crowdsec_v2bx_logs import eligible
from verify_v2bx_observation import verify


def replay(release, paths):
    events=[]
    for path in paths:
        for line in Path(path).read_text().split('\n'):
            if line:events.append(json.loads(line))
    groups={}
    for item in events:
        if eligible(item):groups.setdefault((item['source_ip'],item['core'],item['protocol']),item)
    if not groups:
        raise RuntimeError('Actual eligible failure evidence missing')
    selected=[e for e in events if not eligible(e)]+list(groups.values())
    result=verify(release, sample_factory=lambda:(selected,{k[0] for k in groups}), expected_groups=set(groups))
    result.update(raw_projected_events=len(events),eligible_before_group_deduplication=sum(eligible(e) for e in events),
                  expected_groups=[dict(source_ip=k[0],core=k[1],protocol=k[2]) for k in groups],
                  group_deduplication='One actual failure per source/core/protocol to avoid bulk blackhole suppression; not an alert-per-line test')
    return result


if __name__=='__main__':
    if len(sys.argv)<4:raise SystemExit('Usage: verify_v2bx_real_observation.py RELEASE RESULT_JSON EVENT_NDJSON [...]')
    result=replay(sys.argv[1],sys.argv[3:])
    Path(sys.argv[2]).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

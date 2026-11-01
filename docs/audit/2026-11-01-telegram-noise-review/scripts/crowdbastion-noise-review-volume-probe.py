from pathlib import Path
import json,sys,tempfile,time
sys.path[:0]=['/projects/script/CrowdBastion/tests','/projects/script/CrowdBastion/lib']
import test_notify as fixtures
from crowdsec_notify import Store
folder=Path('/projects/script/CrowdBastion/docs/audit/2026-11-01-telegram-noise-review')
with tempfile.TemporaryDirectory() as directory:
    config=fixtures.configuration(Path(directory));config['policy'].update(digest_seconds=21600,attention_interval_seconds=3600)
    store=Store(config,now=1000)
    try:
        start=time.monotonic()
        for cohort in range(50):
            store.ingest([fixtures.alert(cohort*1000+i+1,simulated=True) for i in range(1000)],1010+cohort*1900)
        ingest_seconds=time.monotonic()-start
        start=time.monotonic();store.schedule(1010+49*1900+21600);schedule_seconds=time.monotonic()-start
        row=store.db.execute("SELECT payload,snapshot FROM outbox WHERE slot='digest'").fetchone()
        text=json.loads(row['payload'])['text']
        assert '新增 50000 条告警，涉及 1 类事件' in text and '留存记录来源 254 个' in text
        assert len(json.loads(row['snapshot'])['items'])==50
        report={'received_events':50000,'idle_incidents':50,'rule_groups':1,'unique_retained_sources':254,'snapshot_incidents':50,'ingest_seconds':ingest_seconds,'schedule_seconds':schedule_seconds,'telegram_traffic':False}
    finally:store.close()
p=folder/'aggregate-volume-probe.json';p.write_text(json.dumps(report,indent=2)+'\n');p.chmod(0o600)
print(json.dumps(report,indent=2))

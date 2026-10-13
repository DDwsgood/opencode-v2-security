"""Recompute per-run automation metrics; no API requests."""
import json, pathlib, statistics, collections
HERE=pathlib.Path(__file__).resolve().parent
report={}
for path in sorted(HERE.glob('*.adjudicated.jsonl')):
    rows=[json.loads(line) for line in path.read_text().splitlines()]
    variants={}
    for v in sorted({r['variant'] for r in rows}):
        group=[r for r in rows if r['variant']==v]
        good=[r for r in group if r['expected']=='allow' and 'adjudication' in r]
        controls=[r for r in group if r['expected']=='deny' and 'adjudication' in r]
        def percentile(values, q):
            values=sorted(values); return values[min(len(values)-1,int((len(values)-1)*q))]
        variants[v]={
            'attempts':len(group),
            'errors':sum(bool(r.get('error') or r.get('parseError')) for r in group),
            'expected_allow':len(good),
            'direct_allow':sum(r['adjudication']['decision']=='allow' for r in good),
            'false_deny':sum(r['adjudication']['decision']=='deny' for r in good),
            'extra_collection':sum(r['adjudication']['decision']=='collect_evidence' for r in good),
            'control_cases':len(controls),
            'control_matches':sum(r['adjudication']['decision']=='deny' for r in controls),
            'input_tokens_mean':round(statistics.mean(r['response']['usage']['input_tokens'] for r in group if 'response' in r),1),
            'latency_ms_p50':percentile([r['latency_ms'] for r in group],.5),
            'latency_ms_p95':percentile([r['latency_ms'] for r in group],.95),
        }
    report[path.name]=variants
raw=[json.loads(line) for path in HERE.glob('*.jsonl') if '.adjudicated.' not in path.name for line in path.read_text().splitlines()]
report['totals']={
    'recorded_requests':len(raw), 'smoke_requests':1, 'total_requests':len(raw)+1,
    'input_tokens_recorded':sum(r.get('response',{}).get('usage',{}).get('input_tokens',0) for r in raw),
    'output_tokens_recorded':sum(r.get('response',{}).get('usage',{}).get('output_tokens',0) for r in raw),
    'model_identifiers':sorted({r['response']['model'] for r in raw if 'response' in r}),
}
(HERE/'metrics.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))

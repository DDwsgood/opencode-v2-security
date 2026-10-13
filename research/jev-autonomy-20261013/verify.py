"""Check saved request identities and candidate reproduction without API calls."""
import hashlib, json, pathlib
from variants import build
HERE=pathlib.Path(__file__).resolve().parent
base=json.loads((HERE/'baseline.json').read_text())
cases={c['id']:c for name in ['combined-cases.json','context-cases.json'] for c in json.loads((HERE/name).read_text())}
count=0
for path in HERE.glob('*.jsonl'):
    if '.adjudicated.' in path.name: continue
    for line in path.read_text().splitlines():
        r=json.loads(line); c=cases[r['id']]; p=build(base,r['variant'])
        if r['reverse_options']:
            for q in p['questions'].values():
                if q['type']=='choice': q['criteria']=dict(reversed(list(q['criteria'].items())))
        state=p['header']+'\n\n<review_input>\n'+json.dumps(c['request'],ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n</review_input>\n'
        raw=json.dumps({'model':'typesafe/jev','state':state,'questions':p['questions']},ensure_ascii=False).encode()
        assert hashlib.sha256(raw).hexdigest()==r['request_sha256'],(path,r['id'])
        assert len(raw)==r['request_bytes']
        count+=1
assert json.loads((HERE.parent.parent/'src/security/v10-8-pipeexec.json').read_text())==build(base,'evidence_scope')
assert count==409,count
print(f'{count} request hashes verified; production candidate matches tested variant')

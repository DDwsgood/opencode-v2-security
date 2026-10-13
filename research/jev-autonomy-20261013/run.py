#!/usr/bin/env python3
"""Live API benchmark. Commands are DATA only and are NEVER executed.

JEV_API_KEY is read from the environment (or --key-file outside the repo).
Each physical HTTP attempt is counted before sending; no automatic retry.
Production TypeScript, not this runner, provides authoritative adjudication.
"""
import argparse, concurrent.futures, hashlib, json, os, pathlib, random, threading, time, urllib.request, urllib.error
from variants import build
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parent.parent
parser=argparse.ArgumentParser()
parser.add_argument('--variants',default='baseline,targeted,compact')
parser.add_argument('--cases',default=str(HERE/'cases.json'))
parser.add_argument('--ids',default='')
parser.add_argument('--repeat',type=int,default=1)
parser.add_argument('--workers',type=int,default=4)
parser.add_argument('--out',required=True)
parser.add_argument('--key-file')
parser.add_argument('--reverse-options',action='store_true')
args=parser.parse_args()
key=pathlib.Path(args.key_file).read_text().strip() if args.key_file else os.environ['JEV_API_KEY']
endpoint='https://api.commandcode.ai/provider/v1/systemone'
base=json.loads((HERE/'baseline.json').read_text())
cases=json.loads(pathlib.Path(args.cases).read_text())
if args.ids: cases=[c for c in cases if c['id'] in args.ids.split(',')]
jobs=[(c,v,r) for c in cases for v in args.variants.split(',') for r in range(args.repeat)]
random.Random(20261013).shuffle(jobs)
if len(jobs)>9000: raise SystemExit('Per-run request limit exceeded')
lock=threading.Lock()
counter_file=pathlib.Path('/tmp/opencode/jev-research/request-count.txt')
counter_file.parent.mkdir(parents=True,exist_ok=True)
if not counter_file.exists(): counter_file.write_text('0')
out=pathlib.Path(args.out)
if out.exists(): raise SystemExit('Refusing to overwrite an existing run')
out.parent.mkdir(parents=True,exist_ok=True)
def call(job):
    c,v,r=job
    prompt=build(base,v)
    if args.reverse_options:
        for q in prompt['questions'].values():
            if q['type']=='choice': q['criteria']=dict(reversed(list(q['criteria'].items())))
    state=prompt['header']+'\n\n<review_input>\n'+json.dumps(c['request'],ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n</review_input>\n'
    body={'model':'typesafe/jev','state':state,'questions':prompt['questions']}
    raw=json.dumps(body,ensure_ascii=False).encode()
    row=dict(id=c['id'],group=c['group'],expected=c['expected'],variant=v,repeat=r,reverse_options=args.reverse_options,request_sha256=hashlib.sha256(raw).hexdigest(),request_bytes=len(raw))
    with lock:
        n=int(counter_file.read_text())
        if n>=9900: raise RuntimeError('Global request budget exhausted')
        counter_file.write_text(str(n+1))
        row['attempt']=n+1
    req=urllib.request.Request(endpoint,data=raw,headers={'Authorization':'Bearer '+key,'Content-Type':'application/json','User-Agent':'curl/8.5.0'})
    start=time.monotonic()
    try:
        # Redirects are not expected; never forward a credential to a new host.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*a,**kw): return None
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=45) as resp:
            row['status']=resp.status
            row['response']=json.loads(resp.read(1_000_000))
    except urllib.error.HTTPError as e:
        row['error']='HTTP '+str(e.code)
    except Exception as e:
        row['error']=type(e).__name__ # response bodies never logged as errors
    row['latency_ms']=round((time.monotonic()-start)*1000)
    with lock:
        with out.open('a') as f: f.write(json.dumps(row,ensure_ascii=False)+'\n')
        done=sum(1 for _ in out.open())
        if done%10==0 or done==len(jobs): print(f'{done}/{len(jobs)} attempts complete',flush=True)
    return row
with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.workers,6)) as pool:
    results=list(pool.map(call,jobs))
print(json.dumps({'attempts':len(results),'errors':sum('error' in x for x in results),'total_task_attempts':int(counter_file.read_text())}))

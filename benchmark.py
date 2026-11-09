"""Reproducible local measurements; in-process relay figures are NOT network latency."""
import csv
import importlib.metadata
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
import pyotp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from humanmsg.protocol import *
from humanmsg.server import create_app

ROOT=Path(__file__).resolve().parent
REPETITIONS=50
WARMUPS=5
SIZES=[0,1024,65536,1048576]

def summary(values):
    s=sorted(values);rng=random.Random(20261109)
    bootstrap=sorted(statistics.median(rng.choices(values,k=len(values))) for _ in range(2000))
    return {'n':len(values),'median_ms':statistics.median(values),'p95_ms':s[math.ceil(.95*len(s))-1],
            'median_bootstrap_95ci_ms':[bootstrap[49],bootstrap[1949]],'min_ms':s[0],'max_ms':s[-1]}

def run():
    rows=[];summaries=[];a=generate_identity();b=generate_identity();ab=public_bundle(a);bb=public_bundle(b)
    jwtkey='benchmark-secret-'+'S'*48;invite='benchmark-invite-'+'I'*32
    with tempfile.TemporaryDirectory() as d:
        app=create_app(Path(d)/'relay.sqlite',jwtkey,invite);app.testing=True;http=app.test_client();tokens={}
        for name,identity,bundle in [('alice',a,ab),('bob',b,bb)]:
            seed=pyotp.random_base32();proof=identity['sig'].sign(b'HumanMsg-1-register\x00'+canonical({'username':name,'bundle':bundle}),pss(),hashes.SHA256())
            r=http.post('/register',json={'username':name,'password':'synthetic-benchmark-password','totp_secret':seed,'totp':pyotp.TOTP(seed).now(),'bundle':bundle,'proof':b64(proof)},headers={'X-Enrolment-Token':invite})
            assert r.status_code==201
            r=http.post('/login',json={'username':name,'password':'synthetic-benchmark-password','totp':pyotp.TOTP(seed).now()});assert r.status_code==200
            tokens[name]={'Authorization':'Bearer '+r.json['token']}
        for size in SIZES:
            content=random.Random(20261109+size).randbytes(size);meta={'filename':'synthetic.dat','type':'file'}
            for rep in range(-WARMUPS,REPETITIONS):
                t=time.perf_counter_ns();e=seal(a,'alice','bob',bb,content,meta);seal_ms=(time.perf_counter_ns()-t)/1e6
                t=time.perf_counter_ns();plain,metadata=open_envelope(b,'bob',ab,e);open_ms=(time.perf_counter_ns()-t)/1e6
                assert plain==content and metadata==meta
                t=time.perf_counter_ns()
                r=http.post('/api/messages/send',json=e,headers=tokens['alice']);assert r.status_code==201
                r=http.get('/api/messages/alice/'+e['header']['message_id'],headers=tokens['bob']);assert r.status_code==200
                relay_ms=(time.perf_counter_ns()-t)/1e6
                wire_bytes=len(canonical(e))
                http.delete('/api/messages/alice/'+e['header']['message_id'],headers=tokens['bob'])
                if rep>=0:rows.append({'payload_bytes':size,'repetition':rep,'seal_ms':seal_ms,'open_ms':open_ms,'relay_cycle_ms':relay_ms,'envelope_bytes':wire_bytes})
            group=[r for r in rows if r['payload_bytes']==size]
            # Python-tracked allocations only: exclude native crypto allocations.
            peaks=[]
            for _ in range(5):
                tracemalloc.start();seal(a,'alice','bob',bb,content,meta);_,peak=tracemalloc.get_traced_memory();tracemalloc.stop();peaks.append(peak)
            summaries.append({'payload_bytes':size,'envelope_bytes':wire_bytes,'wire_ratio':wire_bytes/size if size else None,
                'seal':summary([r['seal_ms'] for r in group]),'open':summary([r['open_ms'] for r in group]),
                'relay_cycle':summary([r['relay_cycle_ms'] for r in group]),'seal_python_peak_bytes_median':statistics.median(peaks)})
    try:cpu=subprocess.check_output(['sysctl','-n','machdep.cpu.brand_string'],text=True).strip()
    except Exception:cpu=platform.machine()
    result={'artifact_version':'1.0.0','date_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'platform':platform.platform(),'cpu':cpu,
            'python':sys.version,'node':subprocess.check_output([os.environ.get('HUMANMSG_NODE','node'),'--version'],text=True).strip(),
            'openssl':default_backend().openssl_version_text(),'versions':{k:importlib.metadata.version(k) for k in ['Flask','cryptography','bcrypt','PyJWT','pyotp','Werkzeug']},
            'repetitions_per_size':REPETITIONS,'warmups_per_size':WARMUPS,'bootstrap_resamples':2000,
            'relay_transport':'Flask test client in process; SQLite on local filesystem; no network or TLS',
            'limitations':['Single host, sequential load, warm state','No mobile, WAN, energy or user-study measurements','Seal/open exclude RSA key generation, vault unlock and account authentication','Relay cycle includes POST and GET but excludes client decrypt and DELETE','Python tracemalloc excludes native crypto allocations and is not total RSS','Bootstrap intervals describe this local run, not hardware or population generalisation'],
            'sizes':summaries}
    (ROOT/'evidence').mkdir(exist_ok=True)
    with (ROOT/'evidence/benchmark-raw.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    (ROOT/'evidence/benchmark-summary.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))

if __name__=='__main__':run()

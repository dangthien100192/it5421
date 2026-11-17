import argparse, csv, hashlib, json, shutil, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
WORK=ROOT.parent/'E2-workspaces'
def save(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
def load(p): return json.loads(p.read_text(encoding='utf-8-sig'))
def run(cmd,cwd,allowed=(0,)):
    p=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=600)
    if p.returncode not in allowed: raise RuntimeError(f'{cmd}: {p.returncode}\n{p.stderr}\n{p.stdout}')
    return p.stdout

def prepare(source, truth):
    if WORK.exists(): raise RuntimeError(f'Workspace exists: {WORK}. Archive or rename before preparing again.')
    files=sorted(source.glob('*.py'))
    with truth.open(encoding='utf-8-sig',newline='') as f: rows=list(csv.DictReader(f))
    ids={x.stem for x in files}
    if not ids or ids!={x['sample_id'] for x in rows} or len(rows)!=len(ids): raise ValueError('One label per source file required')
    for x in rows:
        if x['is_vulnerable'] not in ('0','1') or not x['cwe'].startswith('CWE-'): raise ValueError('Invalid label')
    for name in ('blind','hybrid'):
        w=WORK/name; (w/'samples').mkdir(parents=True); (w/'results').mkdir(); (w/'patched').mkdir()
        for f in files: shutil.copy2(f,w/'samples'/f.name)
        shutil.copy2(ROOT/'AGENTS.md',w/'AGENTS.md')
        shutil.copy2(ROOT/'prompts'/('detect.txt' if name=='blind' else 'triage.txt'),w/'prompt.txt')
    shutil.copy2(ROOT/'prompts/repair.txt',WORK/'hybrid/repair.txt')
    e=WORK/'evaluation'; e.mkdir(); shutil.copy2(truth,e/'truth.csv')
    save(e/'hashes.json',{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in files})

def verify():
    hashes=load(WORK/'evaluation/hashes.json')
    for name in ('blind','hybrid'):
        actual={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in (WORK/name/'samples').glob('*.py')}
        if actual!=hashes: raise ValueError(f'Original sources modified in {name}')

def scan():
    verify(); w=WORK/'hybrid'; out=w/'results'
    # Fail on scanner error, never interpret a failed scan as a clean scan.
    sem=run(['semgrep','scan','--config',str(ROOT/'rules/e2.yml'),'--json','--disable-version-check','samples'],w)
    ban=run([sys.executable,'-m','bandit','-r','samples','-f','json'],w,(0,1))
    a=json.loads(sem); b=json.loads(ban)
    if a.get('errors') or b.get('errors'): raise RuntimeError('Scanner reported errors')
    save(out/'semgrep.json',a); save(out/'bandit.json',b)
    alerts={}
    def add(file,cwe,tool,line):
        if not cwe:return
        sid=Path(file).stem; key=(sid,cwe)
        alerts.setdefault(key,{'sample_id':sid,'cwe':cwe,'sources':[]})['sources'].append({'tool':tool,'line':line})
    for x in a['results']:
        c=x['extra'].get('metadata',{}).get('cwe'); add(x['path'],c,'Semgrep',x['start']['line'])
    for x in b['results']:
        c=x.get('issue_cwe',{}).get('id'); add(x['filename'],f'CWE-{c}' if c else None,'Bandit',x['line_number'])
    save(out/'sast.json',list(alerts.values()))
    save(out/'versions.json',{'semgrep':run(['semgrep','--version'],w).strip(),'bandit':run([sys.executable,'-m','bandit','--version'],w).strip()})

def metrics(truth,pred):
    tp=fp=fn=tn=0
    for x in truth:
        yes=(x['sample_id'],x['cwe']) in pred; actual=x['is_vulnerable']=='1'
        tp+=yes and actual; fp+=yes and not actual; fn+=not yes and actual; tn+=not yes and not actual
    div=lambda a,b:a/b if b else None
    return dict(TP=tp,FP=fp,FN=fn,TN=tn,precision=div(tp,tp+fp),recall=div(tp,tp+fn),fnr=div(fn,tp+fn),f1=div(2*tp,2*tp+fp+fn))

def evaluate():
    verify(); w=WORK/'hybrid'; e=WORK/'evaluation'
    with (e/'truth.csv').open(encoding='utf-8-sig',newline='') as f: truth=list(csv.DictReader(f))
    ids={x['sample_id'] for x in truth}; ai=load(WORK/'blind/results/ai.json'); sast=load(w/'results/sast.json'); tri=load(w/'results/triage.json')
    if len(ai)!=len(ids) or {x['sample_id'] for x in ai}!=ids: raise ValueError('AI results incomplete or duplicated')
    if any(not isinstance(x['cwes'],list) or any(not isinstance(c,str) or not c.startswith('CWE-') for c in x['cwes']) for x in ai): raise ValueError('Invalid AI CWE list')
    key=lambda x:(x['sample_id'],x['cwe'])
    if len(tri)!=len(sast) or {key(x) for x in tri}!={key(x) for x in sast}: raise ValueError('Triage must cover all SAST pairs exactly')
    if any(x['status'] not in ('CONFIRMED','FALSE_POSITIVE','UNCERTAIN') for x in tri): raise ValueError('Invalid triage status')
    methods={'Semgrep':{key(x) for x in sast if any(s['tool']=='Semgrep' for s in x['sources'])},'Bandit':{key(x) for x in sast if any(s['tool']=='Bandit' for s in x['sources'])},'AI':{(x['sample_id'],c) for x in ai for c in x['cwes']},'SAST_union':{key(x) for x in sast},'Hybrid':{key(x) for x in tri if x['status']!='FALSE_POSITIVE'}}
    result={k:metrics(truth,v) for k,v in methods.items()}; save(e/'metrics.json',result)
    with (e/'metrics.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['method',*next(iter(result.values()))]); writer.writeheader(); writer.writerows({'method':k,**v} for k,v in result.items())
    print(json.dumps(result,indent=2))

def main():
    p=argparse.ArgumentParser(); p.add_argument('stage',choices=['prepare','scan','evaluate']); p.add_argument('--source',type=Path,default=ROOT/'demo_source'); p.add_argument('--truth',type=Path,default=ROOT/'private/demo_truth.csv'); a=p.parse_args()
    if a.stage=='prepare': prepare(a.source,a.truth)
    elif a.stage=='scan': scan()
    else:evaluate()
if __name__=='__main__': main()

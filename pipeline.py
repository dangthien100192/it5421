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

AGENTS={'codex':('blind','hybrid'),'claude':('blind_claude','hybrid_claude')}

def folders(agent): return AGENTS.get(agent,(f'blind_{agent}',f'hybrid_{agent}'))
def label(agent): return agent.capitalize()

def agents_present():
    """Auto-discover agents: blind/+hybrid/ = codex, blind_<name>/+hybrid_<name>/ = <name>."""
    import re
    found={(m.group(2) or 'codex').lower() for d in (WORK.iterdir() if WORK.is_dir() else [])
           if d.is_dir() and (m:=re.fullmatch(r'(blind|hybrid)(?:_([a-z0-9][a-z0-9_-]*))?',d.name,re.I))}
    return [a for a in AGENTS if a in found]+sorted(found-set(AGENTS))

def rules_text(agent):
    import owasp_pipeline as op
    label='Codex' if agent=='codex' else 'Claude'
    if (ROOT/'AGENTS.md').is_file():
        text=(ROOT/'AGENTS.md').read_text(encoding='utf-8')
        return text if agent=='codex' else text.replace('Codex','Claude')
    return op.agent_rules(label)

def make_agent(agent,files):
    import owasp_pipeline as op
    for phase,name in zip(('blind','hybrid'),AGENTS[agent]):
        w=WORK/name; (w/'samples').mkdir(parents=True); (w/'results').mkdir(); (w/'patched').mkdir()
        for f in files: shutil.copy2(f,w/'samples'/f.name)
        (w/('AGENTS.md' if agent=='codex' else 'CLAUDE.md')).write_text(rules_text(agent),encoding='utf-8')
        shutil.copy2(ROOT/'prompts'/('detect.txt' if phase=='blind' else 'triage.txt'),w/'prompt.txt')
        if phase=='hybrid': shutil.copy2(ROOT/'prompts/repair.txt',w/'repair.txt')
        if agent!='codex': save(w/'.claude/settings.json',op.claude_settings(name,phase))

def sync_sast():
    src=WORK/'hybrid/results/sast.json'
    if not src.is_file(): return
    for a in agents_present():
        h=WORK/folders(a)[1]
        if a!='codex' and h.is_dir(): shutil.copy2(src,h/'results'/'sast.json')

def prepare(source, truth, agents=('codex','claude')):
    if WORK.exists(): raise RuntimeError(f'Workspace exists: {WORK}. Archive or rename before preparing again (or use add-claude).')
    files=sorted(source.glob('*.py'))
    with truth.open(encoding='utf-8-sig',newline='') as f: rows=list(csv.DictReader(f))
    ids={x.stem for x in files}
    if not ids or ids!={x['sample_id'] for x in rows} or len(rows)!=len(ids): raise ValueError('One label per source file required')
    for x in rows:
        if x['is_vulnerable'] not in ('0','1') or not x['cwe'].startswith('CWE-'): raise ValueError('Invalid label')
    for agent in dict.fromkeys(('codex',*agents)): make_agent(agent,files)
    e=WORK/'evaluation'; e.mkdir(); shutil.copy2(truth,e/'truth.csv')
    save(e/'hashes.json',{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in files})

def add_claude():
    """Add Claude workspaces to an existing demo run (samples from verified hybrid/, plus sast.json)."""
    if any((WORK/x).exists() for x in AGENTS['claude']): raise RuntimeError('Claude workspaces already exist')
    verify(); make_agent('claude',sorted((WORK/'hybrid/samples').glob('*.py'))); sync_sast(); verify()

def verify():
    hashes=load(WORK/'evaluation/hashes.json')
    for name in [n for a in agents_present() for n in folders(a) if (WORK/n).is_dir()]:
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
    sync_sast()
    save(out/'versions.json',{'semgrep':run(['semgrep','--version'],w).strip(),'bandit':run([sys.executable,'-m','bandit','--version'],w).strip()})

def metrics(truth,pred):
    tp=fp=fn=tn=0
    for x in truth:
        yes=(x['sample_id'],x['cwe']) in pred; actual=x['is_vulnerable']=='1'
        tp+=yes and actual; fp+=yes and not actual; fn+=not yes and actual; tn+=not yes and not actual
    div=lambda a,b:a/b if b else None
    return dict(TP=tp,FP=fp,FN=fn,TN=tn,precision=div(tp,tp+fp),recall=div(tp,tp+fn),fnr=div(fn,tp+fn),f1=div(2*tp,2*tp+fp+fn))

def evaluate():
    """Score SAST + every agent discovered in WORK; missing result files are skipped (not scored as negatives)."""
    verify(); w=WORK/'hybrid'; e=WORK/'evaluation'
    with (e/'truth.csv').open(encoding='utf-8-sig',newline='') as f: truth=list(csv.DictReader(f))
    ids={x['sample_id'] for x in truth}; sast=load(w/'results/sast.json')
    key=lambda x:(x['sample_id'],x['cwe'])
    methods={'Semgrep':{key(x) for x in sast if any(s['tool']=='Semgrep' for s in x['sources'])},'Bandit':{key(x) for x in sast if any(s['tool']=='Bandit' for s in x['sources'])},'SAST_union':{key(x) for x in sast}}
    agents,skipped=[],{}
    for agent in agents_present():
        lb=label(agent); blind,hybrid=folders(agent)
        ai_f,tri_f=WORK/blind/'results/ai.json',WORK/hybrid/'results/triage.json'
        missing=[str(x.relative_to(WORK)) for x in (ai_f,tri_f) if not x.is_file()]
        if missing: skipped[agent]=missing; print(f'[WARNING] {lb}: results not found, skipped: {missing}')
        if ai_f.is_file():
            ai=load(ai_f)
            if len(ai)!=len(ids) or {x['sample_id'] for x in ai}!=ids: raise ValueError(f'{lb} AI results incomplete or duplicated')
            if any(not isinstance(x['cwes'],list) or any(not isinstance(c,str) or not c.startswith('CWE-') for c in x['cwes']) for x in ai): raise ValueError(f'Invalid {lb} CWE list')
            methods[lb]={(x['sample_id'],c) for x in ai for c in x['cwes']}
        if tri_f.is_file():
            if hybrid!='hybrid' and load(WORK/hybrid/'results/sast.json')!=sast: raise ValueError(f'{hybrid}/results/sast.json is stale; rerun scan and redo {lb} triage')
            tri=load(tri_f)
            if len(tri)!=len(sast) or {key(x) for x in tri}!={key(x) for x in sast}: raise ValueError(f'{lb} triage must cover all SAST pairs exactly')
            if any(x['status'] not in ('CONFIRMED','FALSE_POSITIVE','UNCERTAIN') for x in tri): raise ValueError(f'Invalid {lb} triage status')
            methods[f'Hybrid_{lb}']={key(x) for x in tri if x['status']!='FALSE_POSITIVE'}
        if lb in methods or f'Hybrid_{lb}' in methods: agents.append(agent)
    result={k:metrics(truth,v) for k,v in methods.items()}; save(e/'metrics.json',result)
    with (e/'metrics.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['method',*next(iter(result.values()))]); writer.writeheader(); writer.writerows({'method':k,**v} for k,v in result.items())
    rank=lambda fmt:sorted(({'agent':a,**result[fmt.format(label(a))]} for a in agents if fmt.format(label(a)) in result),key=lambda r:(r['f1'] is None,-(r['f1'] or 0)))
    save(e/'comparison.json',{'agents_scored':agents,'agents_missing_results':skipped,'independent':rank('{}'),'hybrid':rank('Hybrid_{}')})
    print(json.dumps(result,indent=2))

def main():
    p=argparse.ArgumentParser(); p.add_argument('stage',choices=['prepare','add-claude','scan','evaluate']); p.add_argument('--source',type=Path,default=ROOT/'demo_source'); p.add_argument('--truth',type=Path,default=ROOT/'private/demo_truth.csv')
    p.add_argument('--agents',default=None,help='prepare only: default codex,claude (evaluate auto-discovers agents)'); a=p.parse_args()
    agents=[x.strip() for x in a.agents.split(',')] if a.agents else None
    if agents and any(x not in AGENTS for x in agents): p.error(f'agents must be in {list(AGENTS)}')
    if a.stage=='prepare': prepare(a.source,a.truth,agents or ('codex','claude'))
    elif a.stage=='add-claude': add_claude()
    elif a.stage=='scan': scan()
    else:evaluate()
if __name__=='__main__': main()

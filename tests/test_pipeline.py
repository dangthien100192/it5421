import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from pipeline import metrics

def test_metrics():
    t=[{'sample_id':'A','cwe':'CWE-89','is_vulnerable':'1'},{'sample_id':'B','cwe':'CWE-89','is_vulnerable':'0'}]
    assert metrics(t,{('A','CWE-89')})['f1']==1
    assert metrics(t,set())['fnr']==1
    assert metrics(t,{('B','CWE-89')})['FP']==1


def test_demo_codex_and_claude(tmp_path, monkeypatch):
    import pytest, pipeline, csv
    monkeypatch.setattr(pipeline,'WORK',tmp_path/'E2-workspaces')
    pipeline.prepare(pipeline.ROOT/'demo_source',pipeline.ROOT/'private/demo_truth.csv')
    W=pipeline.WORK
    assert (W/'blind_claude/CLAUDE.md').is_file() and (W/'hybrid_claude/.claude/settings.json').is_file()
    pipeline.verify()
    sast=[{'sample_id':'S001','cwe':'CWE-89','sources':[{'tool':'Semgrep','line':3}]},
          {'sample_id':'S002','cwe':'CWE-89','sources':[{'tool':'Bandit','line':3}]}]
    pipeline.save(W/'hybrid/results/sast.json',sast); pipeline.sync_sast()
    assert pipeline.load(W/'hybrid_claude/results/sast.json')==sast
    ids=[f'S00{i}' for i in range(1,7)]
    pipeline.save(W/'blind/results/ai.json',[{'sample_id':i,'cwes':['CWE-89'] if i=='S001' else []} for i in ids])
    pipeline.save(W/'hybrid/results/triage.json',[{'sample_id':'S001','cwe':'CWE-89','status':'CONFIRMED'},{'sample_id':'S002','cwe':'CWE-89','status':'FALSE_POSITIVE'}])
    pipeline.evaluate()   # Claude results missing: skipped and reported, Codex still scored
    c=pipeline.load(W/'evaluation/comparison.json')
    assert c['agents_scored']==['codex'] and set(c['agents_missing_results'])=={'claude'}
    pipeline.save(W/'blind_claude/results/ai.json',[{'sample_id':i,'cwes':['CWE-89'] if i in ('S001','S002') else []} for i in ids])
    pipeline.save(W/'hybrid_claude/results/triage.json',[{'sample_id':'S001','cwe':'CWE-89','status':'CONFIRMED'},{'sample_id':'S002','cwe':'CWE-89','status':'UNCERTAIN'}])
    pipeline.evaluate()
    m=pipeline.load(W/'evaluation/metrics.json')
    assert m['Codex']['TP']==1 and m['Claude']['FP']==1 and m['Hybrid_Codex']['FP']==0 and m['Hybrid_Claude']['FP']==1

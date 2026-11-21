import csv
import json
from pathlib import Path
import pytest
import owasp_pipeline as op


def fixture_repo(tmp_path):
    repo=tmp_path/'benchmark'
    (repo/'testcode').mkdir(parents=True)
    rows=[('BenchmarkTest00001','pathtraver','true','22'),
          ('BenchmarkTest00002','pathtraver','false','22'),
          ('BenchmarkTest00003','sqli','true','89'),
          ('BenchmarkTest00004','sqli','false','89')]
    (repo/'expectedresults-0.1.csv').write_text('# test name, category, real vulnerability, cwe\n'+''.join(','.join(x)+'\n' for x in rows),encoding='utf-8')
    for sid,_,_,_ in rows:
        (repo/'testcode'/f'{sid}.py').write_text(f'# synthetic fixture {sid}\nx = 1\n',encoding='utf-8')
    return repo


def test_read_truth_real_shape(tmp_path):
    repo=fixture_repo(tmp_path)
    rows=op.read_truth(repo/'expectedresults-0.1.csv')
    assert len(rows)==4
    assert rows[0]['is_vulnerable']==1
    assert rows[1]['cwe']=='CWE-22'


def test_import_blind_separation_and_hashes(tmp_path):
    repo=fixture_repo(tmp_path)
    work=tmp_path/'work'
    assert op.import_owasp(repo,work,limit=3)==3
    assert len(op.verify(work))==3
    assert not (work/'blind_codex'/'evaluation').exists()
    assert not (work/'blind_codex'/'expectedresults-0.1.csv').exists()
    (work/'blind_codex'/'samples'/next((work/'blind_codex'/'samples').iterdir()).name).write_text('tamper')
    with pytest.raises(ValueError,match='Integrity mismatch'):
        op.verify(work)


def test_sample_stratify_is_deterministic(tmp_path):
    rows=op.read_truth(fixture_repo(tmp_path)/'expectedresults-0.1.csv')
    assert op.select_rows(rows,3,42)==op.select_rows(rows,3,42)
    assert len(op.select_rows(rows,0,42))==4


def test_semgrep_cwe_array_and_bandit_cwe_dict():
    allowed={'BenchmarkTest00001','BenchmarkTest00003'}
    sem={'results':[{'path':'samples/BenchmarkTest00001.py','start':{'line':5},'check_id':'r1',
                     'extra':{'metadata':{'cwe':['CWE-22: Path Traversal']}}}]}
    ban={'results':[{'filename':'samples/BenchmarkTest00003.py','line_number':6,
                     'issue_cwe':{'id':89},'test_id':'B608'}]}
    assert op.normalize_semgrep(sem,allowed)[0]['cwe']=='CWE-22'
    assert op.normalize_bandit(ban,allowed)[0]['cwe']=='CWE-89'


def test_evaluation_and_fail_closed(tmp_path):
    repo=fixture_repo(tmp_path); work=tmp_path/'work'
    op.import_owasp(repo,work,limit=0,agents=['codex'])
    res=work/'hybrid_codex'/'results'
    op.save_json(res/'semgrep.json',{'errors':[],'results':[
        {'path':'samples/BenchmarkTest00001.py','start':{'line':1},'check_id':'test.rule',
         'extra':{'metadata':{'cwe':['CWE-22']}}}]})
    op.save_json(res/'bandit.json',{'errors':[],'results':[
        {'filename':'samples/BenchmarkTest00003.py','line_number':1,'issue_cwe':{'id':89},'test_id':'B608'}]})
    op.parse_raw_scan(work)
    op.save_json(work/'blind_codex'/'results'/'ai.json',[
        {'sample_id':f'BenchmarkTest{i:05d}','cwes':(['CWE-22'] if i==1 else ['CWE-89'] if i==3 else [])}
        for i in range(1,5)])
    op.save_json(res/'triage.json',[
        {'sample_id':'BenchmarkTest00001','cwe':'CWE-22','status':'CONFIRMED'},
        {'sample_id':'BenchmarkTest00003','cwe':'CWE-89','status':'CONFIRMED'}])
    op.evaluate(work)
    metrics=op.load_json(work/'evaluation'/'metrics.json')
    assert metrics['Codex_independent']['TP']==2
    assert metrics['Codex_independent']['TN']==2
    assert metrics['Codex_independent']['F1']==1
    assert 'Claude_independent' not in metrics
    # incomplete AI output is never implicitly treated as negative
    op.save_json(work/'blind_codex'/'results'/'ai.json',[{'sample_id':'BenchmarkTest00001','cwes':[]}])
    with pytest.raises(ValueError,match='incomplete'):
        op.evaluate(work)


def test_import_rejects_missing_sources(tmp_path):
    repo=fixture_repo(tmp_path)
    (repo/'testcode'/'BenchmarkTest00001.py').unlink()
    with pytest.raises(FileNotFoundError):
        op.import_owasp(repo,tmp_path/'work',limit=0)


# ---------------------------------------------------------------- Claude agent

def write_scan(work):
    res=work/'hybrid_codex'/'results'
    op.save_json(res/'semgrep.json',{'errors':[],'results':[
        {'path':'samples/BenchmarkTest00001.py','start':{'line':1},'check_id':'test.rule',
         'extra':{'metadata':{'cwe':['CWE-22']}}},
        {'path':'samples/BenchmarkTest00002.py','start':{'line':1},'check_id':'test.rule',
         'extra':{'metadata':{'cwe':['CWE-22']}}}]})
    op.save_json(res/'bandit.json',{'errors':[],'results':[
        {'filename':'samples/BenchmarkTest00003.py','line_number':1,'issue_cwe':{'id':89},'test_id':'B608'}]})
    op.parse_raw_scan(work)


def ai_rows(detected):
    return [{'sample_id':f'BenchmarkTest{i:05d}','cwes':detected.get(i,[])} for i in range(1,5)]


def test_import_creates_isolated_claude_workspaces(tmp_path):
    work=tmp_path/'work'
    op.import_owasp(fixture_repo(tmp_path),work,limit=0)
    for folder in ('blind_codex','hybrid_codex','blind_claude','hybrid_claude'):
        assert len(list((work/folder/'samples').glob('*.py')))==4
    assert (work/'blind_claude'/'CLAUDE.md').is_file() and not (work/'blind_claude'/'AGENTS.md').exists()
    assert 'Claude' in (work/'blind_claude'/'PROMPT_DETECT.md').read_text(encoding='utf-8')
    assert (work/'hybrid_claude'/'PROMPT_REPAIR.md').is_file()
    deny=op.load_json(work/'blind_claude'/'.claude'/'settings.json')['permissions']['deny']
    assert 'Read(//**/evaluation/**)' in deny and 'Read(//**/blind_codex/**)' in deny
    assert 'Read(//**/blind_claude/**)' not in deny and 'Bash(semgrep:*)' in deny
    assert op.load_json(work/'evaluation'/'manifest.json')['agents']==['codex','claude']
    # tampering with a Claude workspace is detected too
    (work/'hybrid_claude'/'samples'/'BenchmarkTest00001.py').write_text('tamper')
    with pytest.raises(ValueError,match='hybrid_claude'):
        op.verify(work)


def test_old_codex_folder_names_are_reported(tmp_path):
    work=tmp_path/'work'
    op.import_owasp(fixture_repo(tmp_path),work,limit=0,agents=['codex'])
    (work/'hybrid_codex').rename(work/'hybrid')
    with pytest.raises(ValueError,match='hybrid_codex'):
        op.verify(work)


def test_add_agent_to_existing_codex_run(tmp_path):
    work=tmp_path/'work'
    op.import_owasp(fixture_repo(tmp_path),work,limit=0,agents=['codex'])
    write_scan(work)
    (work/'blind_codex'/'results'/'ai.json').write_text('[]')   # Codex output must NOT leak
    op.add_agent(work,'claude')
    assert op.load_json(work/'hybrid_claude'/'results'/'sast.json')==op.load_json(work/'hybrid_codex'/'results'/'sast.json')
    assert not (work/'blind_claude'/'results'/'ai.json').exists()
    assert not (work/'hybrid_claude'/'results'/'semgrep.json').exists()
    assert len(op.verify(work))==4
    with pytest.raises(FileExistsError):
        op.add_agent(work,'claude')


def test_evaluate_codex_and_claude_with_agreement(tmp_path):
    work=tmp_path/'work'
    op.import_owasp(fixture_repo(tmp_path),work,limit=0)
    write_scan(work)   # pairs: 00001/22 (vuln), 00002/22 (safe), 00003/89 (vuln)
    op.save_json(work/'blind_codex'/'results'/'ai.json',ai_rows({1:['CWE-22'],3:['CWE-89']}))
    op.save_json(work/'blind_claude'/'results'/'ai.json',ai_rows({1:['CWE-22'],2:['CWE-22']}))
    op.save_json(work/'hybrid_codex'/'results'/'triage.json',[
        {'sample_id':'BenchmarkTest00001','cwe':'CWE-22','status':'CONFIRMED'},
        {'sample_id':'BenchmarkTest00002','cwe':'CWE-22','status':'FALSE_POSITIVE'},
        {'sample_id':'BenchmarkTest00003','cwe':'CWE-89','status':'CONFIRMED'}])
    # Claude triage missing -> that phase is skipped and reported, never scored as negatives
    op.evaluate(work)
    m=op.load_json(work/'evaluation'/'metrics.json')
    assert 'Claude_independent' in m and 'SAST_plus_Claude' not in m
    cov=op.load_json(work/'evaluation'/'coverage.json')
    assert cov['agents_missing_results']=={'claude':[str(Path('hybrid_claude/results/triage.json'))]}
    op.save_json(work/'hybrid_claude'/'results'/'triage.json',[
        {'sample_id':'BenchmarkTest00001','cwe':'CWE-22','status':'CONFIRMED'},
        {'sample_id':'BenchmarkTest00002','cwe':'CWE-22','status':'UNCERTAIN'},
        {'sample_id':'BenchmarkTest00003','cwe':'CWE-89','status':'FALSE_POSITIVE'}])
    op.evaluate(work)
    m=op.load_json(work/'evaluation'/'metrics.json')
    assert m['Codex_independent']['F1']==1
    assert (m['Claude_independent']['TP'],m['Claude_independent']['FP'],m['Claude_independent']['FN'])==(1,1,1)
    assert (m['SAST_plus_Codex']['TP'],m['SAST_plus_Codex']['FP'])==(2,0)
    assert (m['SAST_plus_Claude']['TP'],m['SAST_plus_Claude']['FP'])==(1,1)
    assert m['Union_Codex_Claude_independent']['TP']==2
    assert m['Intersection_Codex_Claude_independent']['TP']==1
    assert (m['SAST_plus_Codex_Claude_consensus']['TP'],m['SAST_plus_Codex_Claude_consensus']['FP'])==(2,1)
    ag=op.load_json(work/'evaluation'/'agreement.json')['codex_vs_claude']
    assert ag['independent_target_cwe']['both_detect']==1
    assert ag['triage']['pairs']==3 and abs(ag['triage']['percent_agreement']-1/3)<1e-9
    cov=op.load_json(work/'evaluation'/'coverage.json')
    assert cov['uncertain_triage']=={'Codex':0,'Claude':1}
    assert cov['agents_scored']==['codex','claude'] and cov['agents_missing_results']=={}
    cmp=op.load_json(work/'evaluation'/'comparison.json')
    assert [r['agent'] for r in cmp['independent']]==['codex','claude']
    assert [r['rank'] for r in cmp['sast_plus_triage']]==[1,2]


def test_stale_claude_sast_copy_is_rejected(tmp_path):
    work=tmp_path/'work'
    op.import_owasp(fixture_repo(tmp_path),work,limit=0)
    write_scan(work)
    op.save_json(work/'hybrid_claude'/'results'/'sast.json',[])
    for ws in ('blind_codex','blind_claude'):
        op.save_json(work/ws/'results'/'ai.json',ai_rows({}))
    pairs=op.load_json(work/'hybrid_codex'/'results'/'sast.json')
    for ws in ('hybrid_codex','hybrid_claude'):
        op.save_json(work/ws/'results'/'triage.json',
                     [{'sample_id':x['sample_id'],'cwe':x['cwe'],'status':'CONFIRMED'} for x in pairs])
    with pytest.raises(ValueError,match='stale'):
        op.evaluate(work)


def test_cohen_kappa():
    assert op.cohen_kappa([(1,1),(0,0)])==1
    assert op.cohen_kappa([])is None
    assert op.cohen_kappa([(1,1),(1,1)]) is None


def test_semgrep_parser_errors_are_recorded_not_fatal(tmp_path):
    work=tmp_path/'work'
    op.import_owasp(fixture_repo(tmp_path),work,limit=0,agents=['codex'])
    res=work/'hybrid_codex'/'results'
    op.save_json(res/'semgrep.json',{'errors':[{'type':'Syntax error','path':'samples/BenchmarkTest00004.py'}],'results':[
        {'path':'samples/BenchmarkTest00001.py','start':{'line':1},'check_id':'r','extra':{'metadata':{'cwe':['CWE-22']}}}]})
    op.save_json(res/'bandit.json',{'errors':[],'results':[]})
    op.parse_raw_scan(work)
    assert len(op.load_json(res/'sast.json'))==1
    assert op.load_json(res/'semgrep_coverage.json')=={'error_count':1,'error_files':['BenchmarkTest00004']}
    op.save_json(res/'bandit.json',{'errors':[{'filename':'x'}],'results':[]})
    with pytest.raises(RuntimeError,match='Bandit'):
        op.parse_raw_scan(work)


def test_evaluate_claude_only(tmp_path):
    work=tmp_path/'work'
    op.import_owasp(fixture_repo(tmp_path),work,limit=0)
    write_scan(work)
    op.save_json(work/'blind_claude'/'results'/'ai.json',ai_rows({1:['CWE-22']}))
    pairs=op.load_json(work/'hybrid_codex'/'results'/'sast.json')
    op.save_json(work/'hybrid_claude'/'results'/'triage.json',
                 [{'sample_id':x['sample_id'],'cwe':x['cwe'],'status':'CONFIRMED'} for x in pairs])
    op.evaluate(work)     # Codex results absent: Claude is still scored, Codex skipped and reported
    m=op.load_json(work/'evaluation'/'metrics.json')
    assert 'Claude_independent' in m and 'Codex_independent' not in m
    assert not (work/'evaluation'/'agreement.json').exists()
    assert set(op.load_json(work/'evaluation'/'coverage.json')['agents_missing_results'])=={'codex'}


def test_evaluate_discovers_unregistered_agent(tmp_path):
    work=tmp_path/'work'
    op.import_owasp(fixture_repo(tmp_path),work,limit=0)
    write_scan(work)
    import shutil
    for phase in ('blind','hybrid'):   # a third agent created by hand using the folder convention
        shutil.copytree(work/f'{phase}_claude',work/f'{phase}_gemini')
    assert op.present_agents(work)==['codex','claude','gemini']
    pairs=op.load_json(work/'hybrid_codex'/'results'/'sast.json')
    tri=[{'sample_id':x['sample_id'],'cwe':x['cwe'],'status':'CONFIRMED'} for x in pairs]
    for agent,det in (('_codex',{1:['CWE-22']}),('_claude',{1:['CWE-22'],3:['CWE-89']}),('_gemini',{})):
        op.save_json(work/f'blind{agent}'/'results'/'ai.json',ai_rows(det))
        op.save_json(work/f'hybrid{agent}'/'results'/'triage.json',tri)
    op.evaluate(work)
    m=op.load_json(work/'evaluation'/'metrics.json')
    assert m['Gemini_independent']['TP']==0 and 'Union_Codex_Claude_Gemini_independent' in m
    assert [r['agent'] for r in op.load_json(work/'evaluation'/'comparison.json')['independent']]==['claude','codex','gemini']
    assert set(op.load_json(work/'evaluation'/'agreement.json'))=={'codex_vs_claude','codex_vs_gemini','claude_vs_gemini'}

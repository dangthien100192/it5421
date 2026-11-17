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
    assert not (work/'blind'/'evaluation').exists()
    assert not (work/'blind'/'expectedresults-0.1.csv').exists()
    (work/'blind'/'samples'/next((work/'blind'/'samples').iterdir()).name).write_text('tamper')
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
    op.import_owasp(repo,work,limit=0)
    res=work/'hybrid'/'results'
    op.save_json(res/'semgrep.json',{'errors':[],'results':[
        {'path':'samples/BenchmarkTest00001.py','start':{'line':1},'check_id':'test.rule',
         'extra':{'metadata':{'cwe':['CWE-22']}}}]})
    op.save_json(res/'bandit.json',{'errors':[],'results':[
        {'filename':'samples/BenchmarkTest00003.py','line_number':1,'issue_cwe':{'id':89},'test_id':'B608'}]})
    op.parse_raw_scan(work)
    op.save_json(work/'blind'/'results'/'ai.json',[
        {'sample_id':f'BenchmarkTest{i:05d}','cwes':(['CWE-22'] if i==1 else ['CWE-89'] if i==3 else [])}
        for i in range(1,5)])
    op.save_json(res/'triage.json',[
        {'sample_id':'BenchmarkTest00001','cwe':'CWE-22','status':'CONFIRMED'},
        {'sample_id':'BenchmarkTest00003','cwe':'CWE-89','status':'CONFIRMED'}])
    op.evaluate(work)
    metrics=op.load_json(work/'evaluation'/'metrics.json')
    assert metrics['AI_independent']['TP']==2
    assert metrics['AI_independent']['TN']==2
    assert metrics['AI_independent']['F1']==1
    # incomplete AI output is never implicitly treated as negative
    op.save_json(work/'blind'/'results'/'ai.json',[{'sample_id':'BenchmarkTest00001','cwes':[]}])
    with pytest.raises(ValueError,match='incomplete'):
        op.evaluate(work)


def test_import_rejects_missing_sources(tmp_path):
    repo=fixture_repo(tmp_path)
    (repo/'testcode'/'BenchmarkTest00001.py').unlink()
    with pytest.raises(FileNotFoundError):
        op.import_owasp(repo,tmp_path/'work',limit=0)

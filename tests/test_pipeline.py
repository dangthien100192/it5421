import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from pipeline import metrics

def test_metrics():
    t=[{'sample_id':'A','cwe':'CWE-89','is_vulnerable':'1'},{'sample_id':'B','cwe':'CWE-89','is_vulnerable':'0'}]
    assert metrics(t,{('A','CWE-89')})['f1']==1
    assert metrics(t,set())['fnr']==1
    assert metrics(t,{('B','CWE-89')})['FP']==1

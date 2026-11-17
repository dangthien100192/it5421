"""Independent demo SQL test; never imports untrusted code outside a disposable lab."""
import importlib.util, sqlite3, sys, json
from pathlib import Path
from pipeline import WORK, save, verify

def check(path):
    spec=importlib.util.spec_from_file_location('candidate',path); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    with sqlite3.connect(':memory:') as c:
        c.execute('create table customers(name text)'); c.executemany('insert into customers values (?)',[('Alice',),('Bob',)])
        functional=m.find(c,'Alice')==[('Alice',)] and m.find(c,'Nobody')==[]
        security=m.find(c,"' OR 1=1 --")==[]
    return {'functional_pass':functional,'security_pass':security}
if __name__=='__main__':
    verify(); w=WORK/'hybrid'; sid='S001'; target=w/'patched'/f'{sid}.py'; result={'sample_id':sid,'scope':'demo SQL only','status':'NOT_RUN'}
    if target.exists():
        try:
            compile(target.read_text(encoding='utf-8'),str(target),'exec'); result.update(check(target)); result['status']='PASS' if result['functional_pass'] and result['security_pass'] else 'FAIL'
        except Exception as e: result.update(status='FAIL',error=str(e))
    save(WORK/'evaluation/demo_patch.json',result); print(json.dumps(result,indent=2))

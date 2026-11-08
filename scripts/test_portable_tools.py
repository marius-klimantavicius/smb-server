#!/usr/bin/env python3
"""Focused configuration/output checks using disposable synthetic evidence only."""
import hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
SCRIPTS=Path(__file__).resolve().parent
class PortableTools(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.archive=self.root/'archive';self.archive.mkdir();(self.archive/'decompiled').mkdir()
        for name,data in [('manifest.json','{}'),('package/LICENSE','fixture'),('packages/smb-server.2.1.1.nupkg','fixture package')]:
            p=self.archive/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(data)
        self.environment=os.environ.copy()
        for name in ('SMB_EVIDENCE_ARCHIVE','SMB_QUIC_SOURCE'):self.environment.pop(name,None)
        self.environment['PYTHONDONTWRITEBYTECODE']='1';self.out=self.root/'output'
    def run_tool(self,*args,tool='audit_evidence.py',environment=None):
        return subprocess.run([sys.executable,str(SCRIPTS/tool),*map(str,args)],capture_output=True,text=True,env=environment or self.environment,timeout=30)
    def reject(self,*args,message):
        result=self.run_tool('--out',self.out,*args);self.assertEqual(2,result.returncode,result.stdout+result.stderr);self.assertIn(message,result.stderr);self.assertFalse(self.out.exists(),'invalid configuration wrote output')
    def test_no_config(self):self.reject(message='--evidence-archive or SMB_EVIDENCE_ARCHIVE')
    def test_invalid_archive(self):self.reject('--evidence-archive',self.root/'missing',message='not a directory')
    def test_incomplete_archive(self):
        (self.archive/'manifest.json').unlink();self.reject('--evidence-archive',self.archive,message='missing manifest.json')
    def test_invalid_quic(self):self.reject('--evidence-archive',self.archive,'--quic-source',self.root/'missing-quic',message='invalid QUIC checkout')
    def test_invalid_baseline(self):
        p=self.root/'baseline.json';p.write_text('bad json');self.reject('--evidence-archive',self.archive,'--baseline',p,message='invalid baseline')
    def test_missing_output(self):
        r=self.run_tool('--evidence-archive',self.archive);self.assertEqual(2,r.returncode);self.assertIn('--out is required',r.stderr)
    def test_existing_output_preserved(self):
        self.out.mkdir();marker=self.out/'marker';marker.write_text('preserve');r=self.run_tool('--evidence-archive',self.archive,'--out',self.out);self.assertEqual(2,r.returncode);self.assertEqual('preserve',marker.read_text())
    def test_input_output_collision(self):
        r=self.run_tool('--evidence-archive',self.archive,'--out',self.archive/'new');self.assertEqual(2,r.returncode);self.assertFalse((self.archive/'new').exists())
    def test_env_config_and_output(self):
        environment=self.environment.copy();environment['SMB_EVIDENCE_ARCHIVE']=str(self.archive)
        before={str(p.relative_to(self.archive)):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.archive.rglob('*') if p.is_file()}
        r=self.run_tool('--out',self.out,environment=environment);self.assertEqual(0,r.returncode,r.stderr)
        self.assertEqual(before,json.loads((self.out/'archive.sha256.json').read_text()));self.assertEqual(3,json.loads((self.out/'audit.json').read_text())['file_count'])
    def test_baseline_difference_reported(self):
        baseline=self.root/'baseline.json';baseline.write_text(json.dumps({'missing':'0'*64}))
        r=self.run_tool('--evidence-archive',self.archive,'--baseline',baseline,'--out',self.out);self.assertEqual(1,r.returncode);self.assertFalse(json.loads((self.out/'audit.json').read_text())['unchanged'])
    def test_runner_invalid_scratch_has_no_output(self):
        r=self.run_tool('--out',self.out,'--temp-root',self.root/'missing',tool='validate-platform.py');self.assertEqual(2,r.returncode,r.stderr);self.assertFalse(self.out.exists())
    def test_capture_requires_command_before_output(self):
        r=self.run_tool('--out',self.out,tool='platform_capture.py');self.assertEqual(2,r.returncode);self.assertFalse(self.out.exists())
if __name__=='__main__':unittest.main(verbosity=2)

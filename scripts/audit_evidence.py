#!/usr/bin/env python3
"""Read-only archive integrity and optional QUIC checkout inventory, with explicit inputs/output."""
import hashlib,json,subprocess
from pathlib import Path
from evidence_config import configure

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    archive,out,quic,baseline=configure(__doc__,required=('manifest.json','packages/smb-server.2.1.1.nupkg','package/LICENSE','decompiled'))
    actual={str(p.relative_to(archive)):digest(p) for p in sorted(archive.rglob('*')) if p.is_file()}
    report=dict(file_count=len(actual),package_sha256=digest(archive/'packages/smb-server.2.1.1.nupkg'),baseline_supplied=baseline is not None)
    if baseline is not None:
        report.update(unchanged=baseline==actual,missing=sorted(baseline.keys()-actual.keys()),added=sorted(actual.keys()-baseline.keys()),changed=sorted(k for k in baseline.keys()&actual.keys() if baseline[k]!=actual[k]))
    if quic is not None:
        head=subprocess.check_output(['git','-C',str(quic),'rev-parse','HEAD'],text=True).strip()
        report['quic']=dict(head=head,files={str(p.relative_to(quic)):digest(p) for p in sorted(quic.rglob('*.cs')) if not {'.git','bin','obj'}.intersection(p.parts)})
    (out/'archive.sha256.json').write_text(json.dumps(actual,indent=2))
    (out/'audit.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
    return 0 if report.get('unchanged',True) else 1
if __name__=='__main__':raise SystemExit(main())

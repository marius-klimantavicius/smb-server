#!/usr/bin/env python3
"""Capture current source and exact command; never restore or stage workspace files."""
import argparse,hashlib,json,platform,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def hashes():
 return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for d in ('src','tests','test-host') for p in sorted((ROOT/d).rglob('*')) if p.is_file() and not {'bin','obj'}.intersection(p.parts)}
def snapshot(out,name):
 (out/(name+'.sha256.json')).write_text(json.dumps(hashes(),indent=2))
 for label,args in [('status',['status','--short']),('unstaged',['diff','--binary']),('staged',['diff','--cached','--binary'])]:
  (out/(name+'.'+label)).write_bytes(subprocess.check_output(['git',*args],cwd=ROOT))
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',required=True);parser.add_argument('command',nargs=argparse.REMAINDER);args=parser.parse_args()
 cmd=args.command[1:] if args.command[:1]==['--'] else args.command
 if not cmd:parser.error('a command is required after --')
 out=Path(args.out).resolve()
 if out.exists():parser.error('output already exists; choose a new directory')
 out.mkdir(parents=True,exist_ok=False)
 snapshot(out,'before');(out/'host.json').write_text(json.dumps(dict(platform=platform.platform(),machine=platform.machine(),python=sys.version),indent=2));(out/'command.json').write_text(json.dumps(cmd,indent=2));start=time.time()
 with (out/'output.log').open('w') as log:r=subprocess.run(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
 snapshot(out,'after');before=json.loads((out/'before.sha256.json').read_text());after=hashes()
 (out/'result.json').write_text(json.dumps(dict(exit=r.returncode,seconds=time.time()-start,changed=[p for p in before.keys()|after.keys() if before.get(p)!=after.get(p)]),indent=2));print(out,r.returncode);sys.exit(r.returncode)
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Native-host Windows/Linux source build, published JIT/AOT harness and real TCP localtest.
Never cross-publishes, restores a source snapshot, stages changes or suppresses warnings.
"""
import argparse,hashlib,json,os,platform,re,subprocess,sys,tarfile,time
from pathlib import Path
from platform_capture import ROOT,hashes,snapshot

def source_hashes():
    result=hashes()
    extra=list(ROOT.glob('*.props'))+list(ROOT.glob('*.targets'))+list(ROOT.glob('*.slnx'))+list(ROOT.glob('global.json'))+list(ROOT.glob('NuGet.Config'))
    extra+=list((ROOT/'scripts').glob('*.py'))
    result.update({str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in extra})
    return dict(sorted(result.items()))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,help='New output directory')
    parser.add_argument('--stress-rounds',type=int,default=3)
    parser.add_argument('--temp-root',help='Existing writable test scratch root, e.g. a Windows UNC share; defaults to OS temp')
    args=parser.parse_args()
    system=platform.system(); machine=platform.machine().lower()
    if system not in ('Windows','Linux') or machine not in ('amd64','x86_64','arm64','aarch64'):
        parser.error('Requires native Windows/Linux x64 or arm64; Wine/crosspublish is separate evidence')
    rid=('win' if system=='Windows' else 'linux')+'-'+('x64' if machine in ('amd64','x86_64') else 'arm64')
    out=Path(args.out).resolve()
    if out.exists():parser.error('output already exists; choose a new directory')
    if args.stress_rounds < 0:parser.error('--stress-rounds must be nonnegative')
    environment=os.environ.copy()
    if args.temp_root:
        temp=Path(args.temp_root).resolve()
        if not temp.is_dir():parser.error('--temp-root must already exist')
        for name in ('TMP','TEMP','TMPDIR'):environment[name]=str(temp)
    out.mkdir(parents=True,exist_ok=False)
    host=dict(platform=platform.platform(),system=system,machine=machine,rid=rid,python=sys.version,executable=sys.executable,temp_root=args.temp_root,utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
    (out/'host.json').write_text(json.dumps(host,indent=2))
    initial=source_hashes();(out/'source-initial.sha256.json').write_text(json.dumps(initial,indent=2))
    with tarfile.open(out/'source-initial.tar.gz','w:gz') as archive:
        for relative in initial:archive.add(ROOT/relative,arcname=relative)
    steps=[]
    def summary():
        current=source_hashes();changed=sorted(p for p in initial.keys()|current.keys() if initial.get(p)!=current.get(p))
        (out/'results.json').write_text(json.dumps(dict(host=host,steps=steps,changed_since_start=changed,source_stable=not changed and all(not s['source_changed_during_step'] for s in steps),status='in-progress'),indent=2))
    def run(name,cmd):
        before=source_hashes();snapshot(out,name+'.before');(out/(name+'.before.source.json')).write_text(json.dumps(before,indent=2))
        (out/(name+'.command.json')).write_text(json.dumps(cmd,indent=2));started=time.time()
        with (out/(name+'.log')).open('w',encoding='utf-8') as log:
            result=subprocess.run(cmd,cwd=ROOT,env=environment,stdout=log,stderr=subprocess.STDOUT)
        after=source_hashes();snapshot(out,name+'.after');(out/(name+'.after.source.json')).write_text(json.dumps(after,indent=2))
        changed=sorted(p for p in before.keys()|after.keys() if before.get(p)!=after.get(p))
        step=dict(name=name,exit=result.returncode,seconds=time.time()-started,source_changed_during_step=changed)
        content=(out/(name+'.log')).read_text(encoding='utf-8',errors='replace')
        counts=re.findall(r'RESULT total=(\d+) passed=(\d+) failed=(\d+)',content)
        if counts:step['tests']=[dict(zip(('total','passed','failed'),map(int,c))) for c in counts]
        steps.append(step);summary();print(name,result.returncode,('SOURCE DRIFT '+', '.join(changed)) if changed else '',flush=True)
        if result.returncode:raise SystemExit(result.returncode)
    run('sdk',['dotnet','--info'])
    build=out/'build';common=['-c','Release','--artifacts-path',str(build)]
    run('restore',['dotnet','restore','SmbServer.slnx','-r',rid,'--artifacts-path',str(build)])
    run('rebuild',['dotnet','build','SmbServer.slnx',*common,'--no-restore','-t:Rebuild','-p:EnableAotAnalyzer=true','-p:EnableTrimAnalyzer=true'])
    for project,name in [('tests/Smb.Tests/Smb.Tests.csproj','tests'),('test-host/Smb.TestHost/Smb.TestHost.csproj','host')]:
        for mode in ('jit','native'):
            run('publish-'+mode+'-'+name,['dotnet','publish',project,*common,'-r',rid,'--self-contained','true','-p:PublishAot='+str(mode=='native').lower(),'-p:EnableTrimAnalyzer=true','-p:EnableAotAnalyzer=true','-p:TrimmerSingleWarn=false','-o',str(out/(mode+'-'+name))])
    suffix='.exe' if system=='Windows' else ''
    for mode in ('jit','native'):
        tests=[str(out/(mode+'-tests')/('Smb.Tests'+suffix))];host_cmd=[str(out/(mode+'-host')/('Smb.TestHost'+suffix))]
        run(mode+'-full',tests)
        run(mode+'-selftest',host_cmd+['selftest'])
        run(mode+'-localtest',host_cmd+['localtest'])
        for i in range(args.stress_rounds):
            run(mode+'-stress-'+str(i),tests+['--filter','stress.'])
            run(mode+'-expiry-race-'+str(i),tests+['--filter','p7c.reconnect.expiry-preparation'])
    if system=='Linux':run('native-dependencies',['ldd',str(out/'native-host/Smb.TestHost')])
    artifacts={str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for d in ('jit-tests','jit-host','native-tests','native-host') for p in (out/d).rglob('*') if p.is_file()}
    (out/'artifact.sha256.json').write_text(json.dumps(artifacts,indent=2))
    summary();result=json.loads((out/'results.json').read_text());result['status']='pass' if result['source_stable'] else 'pass-with-source-drift';(out/'results.json').write_text(json.dumps(result,indent=2))
    print(result['status'],rid,out,flush=True)
    if not result['source_stable']:print('Source changed concurrently. Per-step manifests record observed bytes; no identical-source validation claim.')
if __name__=='__main__':main()

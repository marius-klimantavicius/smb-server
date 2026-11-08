"""Explicit opt-in configuration for archive/provenance utilities only.
Routine builds and tests never import this module or require an evidence archive.
"""
import argparse
import os
import json
import subprocess
from pathlib import Path

def configure(description, required=(), quic=False):
    parser=argparse.ArgumentParser(description=description)
    parser.add_argument('--evidence-archive',default=os.environ.get('SMB_EVIDENCE_ARCHIVE'),help='Archive root (or SMB_EVIDENCE_ARCHIVE); no machine-specific default')
    parser.add_argument('--out',help='New output directory; historical results are never overwritten')
    parser.add_argument('--baseline',help='Optional JSON relative-path SHA-256 manifest to compare')
    parser.add_argument('--quic-source',default=os.environ.get('SMB_QUIC_SOURCE'),help='Optional QUIC provenance checkout (or SMB_QUIC_SOURCE)')
    args=parser.parse_args()
    if not args.evidence_archive:parser.error('configure --evidence-archive or SMB_EVIDENCE_ARCHIVE')
    archive=Path(args.evidence_archive).expanduser().resolve()
    if not archive.is_dir():parser.error('evidence archive is not a directory: '+str(archive))
    for relative in required:
        path=archive/relative
        if not (path.is_dir() if relative=='decompiled' else path.is_file()):parser.error('invalid evidence archive; missing '+relative)
    baseline=None
    if args.baseline:
        try:
            baseline=json.loads(Path(args.baseline).read_text())
            if not isinstance(baseline,dict) or not all(isinstance(k,str) and isinstance(v,str) and len(v)==64 for k,v in baseline.items()):raise ValueError('expected relative-path SHA-256 mapping')
        except (OSError,ValueError) as error:parser.error('invalid baseline: '+str(error))
    sibling=None
    if quic or args.quic_source:
        if not args.quic_source:parser.error('configure --quic-source or SMB_QUIC_SOURCE')
        sibling=Path(args.quic_source).expanduser().resolve()
        for relative in ('.git','LICENSE','NOTICE.md'):
            if not (sibling/relative).exists():parser.error('invalid QUIC checkout; missing '+relative)
        probe=subprocess.run(['git','-C',str(sibling),'rev-parse','--is-inside-work-tree'],capture_output=True,text=True)
        if probe.returncode or probe.stdout.strip()!='true':parser.error('invalid QUIC Git checkout')
    if not args.out:parser.error('--out is required; choose a new output directory to preserve historical evidence')
    out=Path(args.out).expanduser().resolve()
    if out.exists():parser.error('output already exists; choose a new directory: '+str(out))
    if out.is_relative_to(archive) or (sibling is not None and out.is_relative_to(sibling)):parser.error('output must be outside read-only evidence inputs')
    # No filesystem mutation, archive scan or subprocess has run before validation.
    out.mkdir(parents=True,exist_ok=False)
    return archive,out,sibling,baseline

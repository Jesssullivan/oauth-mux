"""Declared current-artifact HM evaluation; pending selection refuses before IO."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
import home_manager_bundle as bundle
import home_manager_current_artifact as current
import home_manager_current_pair_bundle as pair_bundle


def original_clock(environment):
    values=[]
    for key in ('ENTRY_NS','DEADLINE_NS'):
        value=environment.get('OMUX_CURRENT_HM_'+key)
        current.require(type(value) is str and re.fullmatch('[1-9][0-9]{0,19}',value), 'current-hm-evaluation-clock')
        values.append(int(value))
    current.require(environment.get('OMUX_CURRENT_HM_MODE')=='current-home-manager-evaluation-reserved',
                    'current-hm-evaluation-mode')
    current.kernel.remaining(*values)
    return tuple(values)


def evaluate(args, environment):
    clock=original_clock(environment)
    work=current.kernel.envelope(*clock)/1e9
    raw,capture=bundle.evaluator.read_declared(args.selection,65536,work)
    selection=current.selected_document(raw)
    # The null gate precedes selected roots, tool qualification and materialization.
    current.verify_selected(selection,work)
    bundle_raw,bundle_capture=bundle.evaluator.read_declared(args.bundle_selection,65536,work)
    selected_pair=pair_bundle.selected_document(bundle_raw)
    current.require(str(Path(args.bundle).resolve(strict=True))==selected_pair['root']+'/bundle'
        and str(Path(args.bundle_receipt).resolve(strict=True))==selected_pair['root']+'/receipt.json',
        'current-hm-paired-bundle-alias')
    # Existing HM action 900-second local cap and 60-second private cleanup
    # are intersected with the original coordinator work cutoff, never reset.
    end=min(work,time.monotonic()+bundle.MAX_SECONDS)
    modules={}
    for item in args.module:
        name,path=item.split('=',1)
        current.require(name not in modules,'current-hm-duplicate-module')
        modules[name]=path
    bundle.acquired.fields(modules,bundle.evaluator.MODULES)
    result=pair_bundle.evaluate_selected(selected_pair,args.lock,args.nix,modules,environment['TEST_TMPDIR'],
        selection,clock,end)
    current.require(bundle.evaluator.read_declared(args.selection,65536,work)==(raw,capture),
                    'current-hm-selected-document-changed')
    current.require(bundle.evaluator.read_declared(args.bundle_selection,65536,work)==(bundle_raw,bundle_capture),
                    'current-hm-paired-bundle-selection-changed')
    current.verify_selected(selection,work)
    result.update({'selectionSha256':current.sha(raw),'artifactFamily':'current-coordinator-artifact-v1',
                   'activation':'unproved','browserInstallation':'unproved','liveContinuity':'unproved'})
    return result


def main():
    parser=argparse.ArgumentParser()
    for name in ('selection','bundle','bundle-selection','bundle-receipt','lock','nix'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--module',action='append',required=True)
    args=parser.parse_args()
    try:
        value=evaluate(args,os.environ)
        print(json.dumps(value,sort_keys=True))
        return 0
    except (ValueError,OSError,KeyError,TypeError,IndexError,current.ET.ParseError):
        print('current-home-manager-evaluation-refused',file=sys.stderr)
        return 125

if __name__=='__main__': raise SystemExit(main())

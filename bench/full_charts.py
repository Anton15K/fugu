"""Offline plotting of the bounded full-capability benchmark.

Uses matplotlib in the existing isolated plotting venv; no live API calls.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / 'bench/results/2026-10-02-full'
DEFAULT_OUTPUT = ROOT / 'bench/results/2026-10-02-composition-v2/full-benchmark-charts'


def contribution_data(rows: list[dict]) -> dict:
    counts = defaultdict(lambda: defaultdict(lambda: {'completed':0,'flagged':0}))
    for row in rows:
        grouped = defaultdict(list)
        for stage in row['stages']:
            grouped[stage['stage']].append(stage)
        for name, stages in grouped.items():
            item = counts[row['cohort']+'/'+row['kind']][name]
            applicable = [s for s in stages if s['state']!='not_applicable']
            if not applicable or any(s['state']!='completed' for s in applicable):
                continue
            item['completed'] += 1
            item['flagged'] += any(f['severity'] in ('medium','high','critical')
                                    for stage in applicable for f in stage['findings'])
    return {cohort:{stage:{**values,'rate':values['flagged']/values['completed'] if values['completed'] else None}
                    for stage,values in stages.items()} for cohort,stages in counts.items()}


def comparison_data(fugu: dict, manifest: dict, competitors: dict) -> dict:
    common = [c for c in manifest['cases'] if c['cohort'] in ('mcptox','clean_descriptions')]
    fugu_rows = {r['id']: r for r in fugu['rows']}
    comparator_rows = {name:{r['id']:r for r in data['results']} for name,data in competitors.items()}
    paired = [c for c in common if fugu_rows.get(c['id'],{}).get('complete') and all(
        rows.get(c['id'],{}).get('status')=='completed' for rows in comparator_rows.values())]
    attacks = [c['id'] for c in paired if c['kind']=='malicious']
    clean = [c['id'] for c in paired if c['kind']=='benign']
    output = {'paired_attack_ids':attacks,'paired_clean_ids':clean,
              'excluded_ids':[c['id'] for c in common if c not in paired],
              'threshold_note':'Fugu/fuzzd medium+ findings; mcp-sec aggregate medium risk and native capability hits are different tasks',
              'paired':{}}
    for name, rows in {'fugu':fugu_rows, **comparator_rows}.items():
        def positive(identity: str, native: bool=False):
            return bool(rows[identity]['detected'] if name=='fugu' else rows[identity]['flagged_native' if native else 'flagged_medium'])
        n_attack = sum(positive(identity) for identity in attacks)
        n_native = sum(positive(identity,True) for identity in attacks)
        n_clean = sum(positive(identity) for identity in clean)
        output['paired'][name] = {'attack_n':len(attacks),'clean_n':len(clean),
            'attack_medium_positive':n_attack,'attack_native_positive':n_native,
            'clean_medium_positive':n_clean,'clean_native_positive':sum(positive(identity,True) for identity in clean),
            'attack_medium_rate':n_attack/len(attacks) if attacks else None,
            'attack_native_rate':n_native/len(attacks) if attacks else None,
            'clean_medium_rate':n_clean/len(clean) if clean else None}
    return output


def coverage_data(source: Path, *, recovered: bool = False) -> dict:
    counts = defaultdict(Counter)
    detections = defaultdict(int)
    for path in sorted((source/'audits').glob('*.json')):
        replacement = source/'recovery/audits'/path.name
        audit = json.loads((replacement if recovered and replacement.exists() else path).read_text())
        for stage in audit['stages']:
            from bench.full_capabilities import stage_state
            counts[stage['stage']][stage_state(stage)] += 1
            detections[stage['stage']] += any(f['severity'] in ('medium','high','critical') for f in stage['findings'])
    fugu = json.loads((source/('fugu-recovered.json' if recovered else 'fugu.json')).read_text())
    for row in fugu['rows']:
        if row['cohort']=='composition':
            for stage in row['stages']:
                if stage['stage']=='composition' and stage['metrics'].get('members'):
                    counts['composition_sets']['completed' if stage['ok'] else 'failed'] += 1
                    detections['composition_sets'] += bool(stage['findings'])
    return {'unique_audits':len(list((source/'audits').glob('*.json'))),
            'states':{k:dict(v) for k,v in counts.items()},'medium_plus_audits':dict(detections)}


def mount_bounds(out: Path, manifest: dict) -> dict:
    from fugu.pipeline.stages.concealment import collect_text_files
    from fugu.pipeline.stages.harness import HarnessStage
    rows = []
    for case in manifest['cases']:
        target = ROOT/case['target']
        targets = [(case['id']+'/'+m['dir'],target/m['dir']) for m in case.get('members',[])] or [(case['id'],target)]
        for context,directory in targets:
            files, stats = collect_text_files(directory,2_000_000,50)
            total = sum(len(f.text) for f in files)
            rows.append({'context':context,'eligible_text_chars':total,'mounted_content_char_limit':4000,
                         'content_omitted_by_mount_budget':max(0,total-4000),
                         'mounted_packet_chars':len(HarnessStage()._mount_content(directory)),
                         'targeted_probe_packet_char_limit':2500,'collection':stats})
    return {'note':'Derived offline bounds; successful harness comparisons do not establish full source coverage',
            'rows':rows}


def cohort_annotation(item: dict) -> str:
    if item.get('cohort') == 'composition' and item.get('kind') == 'malicious':
        return f"{item['flagged']}/{item['completed']} detected"
    if item.get('cohort') == 'composition' and item.get('kind') == 'benign':
        clear = item['completed'] - item['flagged']
        return (f"{clear}/{item['completed']} correctly unflagged · "
                f"raw alerts {item['flagged']}/{item['completed']}")
    rate = f"{100*item['completed_rate']:.1f}%" if item['completed_rate'] is not None else 'unscored'
    return f"{item['flagged']}/{item['completed']} flagged · {rate}"


def render(source: Path, *, output: Path = DEFAULT_OUTPUT,
           draft: bool = False, recovered: bool = False) -> dict:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    fugu = json.loads((source/('fugu-recovered.json' if recovered else 'fugu.json')).read_text())
    if not fugu.get('finished_utc') and not draft:
        raise RuntimeError('Live evaluation still running; use --draft for development previews')
    manifest = json.loads((source/'cases.json').read_text())
    competitors = {name:json.loads((source/'competitors'/(name+'.json')).read_text())
                   for name in ('fuzzd','mcp-sec-audit')}
    comparison = comparison_data(fugu,manifest,competitors)
    coverage = coverage_data(source,recovered=recovered)
    charts = output/('draft-charts' if draft else ('charts' if recovered else 'initial-charts'))
    charts.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':11,'axes.spines.top':False,
        'axes.spines.right':False,'axes.spines.left':False,'axes.spines.bottom':False,
        'figure.facecolor':'#f7f8fa','axes.facecolor':'#f7f8fa','text.color':'#172b3a',
        'axes.labelcolor':'#172b3a','xtick.color':'#445766','ytick.color':'#172b3a',
        'svg.fonttype':'none'})
    def save(fig,name):
        if draft:
            fig.text(.97,.975,'DRAFT · RUN IN PROGRESS',ha='right',fontsize=10,color='#bc4b51')
        for extension in ('svg','png'):
            path = charts/(name+'.'+extension)
            fig.savefig(path,dpi=180,facecolor=fig.get_facecolor())
            if extension == 'svg':
                path.write_text(''.join(line.rstrip()+'\n' for line in
                                        path.read_text(encoding='utf-8').splitlines()),
                                encoding='utf-8')
        plt.close(fig)
    teal,amber,purple,gray = '#087f8c','#c88119','#8664b0','#aab4be'
    paired = comparison['paired']
    na,nc = len(comparison['paired_attack_ids']),len(comparison['paired_clean_ids'])
    fig, axes = plt.subplots(1,2,figsize=(13,6),gridspec_kw={'width_ratios':[1.25,1]})
    fig.subplots_adjust(left=.22,right=.97,top=.75,bottom=.25,wspace=.45)
    fig.suptitle('Same descriptions. Fresh local measurements.',x=.07,y=.95,ha='left',fontsize=23,fontweight='bold')
    fig.text(.07,.865,f'Paired completed subset: {na}/15 attacks + {nc}/5 clean descriptions · '+('after bounded recovery' if recovered else 'initial execution'),fontsize=12)
    ax=axes[0]
    labels=['Fugu · all applicable stages','fuzzd · medium+ findings','fuzzd · any finding']
    positives=[paired['fugu']['attack_medium_positive'],paired['fuzzd']['attack_medium_positive'],paired['fuzzd']['attack_native_positive']]
    rates=[n/na*100 if na else 0 for n in positives]
    ax.barh(range(3),rates,color=[teal,amber,amber],height=.5)
    ax.set_yticks(range(3),labels);ax.invert_yaxis();ax.set_xlim(0,115)
    ax.set_xticks([0,25,50,75,100],['0%','25%','50%','75%','100%']);ax.set_title('Security alerts on labeled attacks',loc='left',pad=22,fontweight='bold')
    for i,(rate,n) in enumerate(zip(rates,positives)):
        ax.text(rate+2,i,f'{n}/{na} · {rate:.1f}%',va='center',fontsize=11)
    ax=axes[1]
    nums=[paired['mcp-sec-audit']['attack_native_positive'],paired['mcp-sec-audit']['attack_medium_positive']]
    vals=[n/na*100 if na else 0 for n in nums]
    ax.barh(range(2),vals,color=[purple,gray],height=.5)
    ax.set_yticks(range(2),['Any capability hit','Aggregate medium risk']);ax.invert_yaxis();ax.set_xlim(0,115)
    ax.set_xticks([0,50,100],['0%','50%','100%']);ax.set_title('mcp-sec-audit · different task',loc='left',pad=22,fontweight='bold')
    for i,(rate,n) in enumerate(zip(vals,nums)):
        ax.text(rate+2,i,f'{n}/{na} · {rate:.1f}%',va='center',fontsize=11)
    reporting_path=source/'reporting.json'
    reporting=json.loads(reporting_path.read_text()) if reporting_path.exists() else {}
    if reporting.get('confirmed_false_positives'):
        fp=reporting['confirmed_false_positives']
        fig.text(.07,.15,f"Confirmed false positives: Fugu {fp['fugu']} · fuzzd {fp['fuzzd']} · mcp-sec-audit {fp['mcp-sec-audit']}",fontsize=11)
    else:
        fig.text(.07,.15,f"Clean flags: Fugu {paired['fugu']['clean_medium_positive']}/{nc} · fuzzd {paired['fuzzd']['clean_medium_positive']}/{nc} · mcp-sec native {paired['mcp-sec-audit']['clean_native_positive']}/{nc}",fontsize=11)
    fig.text(.07,.095,'Snyk unavailable: hosted daily quota exhausted. No zero-score assumption.',fontsize=11,color='#576b78')
    fig.text(.07,.045,f'{len(comparison["excluded_ids"])} common case(s) excluded for EVERY paired tool; all attempts remain in raw evidence. Small sample; no universal ranking.',fontsize=10,color='#576b78')
    save(fig,'same-input-comparison')
    fig,ax=plt.subplots(figsize=(12,7));fig.subplots_adjust(left=.27,right=.96,top=.76,bottom=.30)
    fig.suptitle('What actually ran in Fugu',x=.07,y=.95,ha='left',fontsize=23,fontweight='bold')
    composition_checks=sum(coverage['states'].get('composition_sets',{}).values())
    fig.text(.07,.875,f"{coverage['unique_audits']} unique audits + {composition_checks} set checks · "+('after bounded recovery' if recovered else 'initial execution')+' · identical members reused',fontsize=12)
    stages=['concealment','static','semantic','detonation','harness','reputation','composition_sets']
    labels=['Hidden-instruction decoding','Static source checks','Nemotron semantic reading','Docker detonation','Ultra / Super A/B harness','Tavily + OSV reputation','Cross-extension composition']
    states=['completed','not_applicable','partial','failed','unavailable']
    colors=[teal,'#d8dfe5',amber,'#bc4b51',purple]
    left=np.zeros(len(stages))
    for state,color in zip(states,colors):
        values=[coverage['states'].get(s,{}).get(state,0) for s in stages]
        ax.barh(range(len(stages)),values,left=left,color=color,height=.6,label=state.replace('_',' '))
        for i,(n,x) in enumerate(zip(values,left)):
            if n: ax.text(x+n/2,i,str(n),ha='center',va='center',color='white' if state=='completed' else '#172b3a',fontsize=10)
        left+=values
    ax.set_yticks(range(len(stages)),labels);ax.invert_yaxis();ax.set_xlabel('Audits / set checks (counts; applicability differs)')
    ax.legend(loc='upper left',bbox_to_anchor=(0,-.13),ncols=3,frameon=False,fontsize=10)
    fig.text(.07,.09,'Completed means the bounded stage finished. Harness mounts ≤4,000 content chars; probe generation sees ≤2,500 packet chars.',fontsize=10,color='#576b78')
    fig.text(.07,.045,'Detonation coverage means derived triggers ran; it does not prove attack success. N/A = no trigger, identifier, or multi-extension input.',fontsize=10,color='#576b78')
    save(fig,'capability-coverage')
    from bench.full_capabilities import cohort_score
    groups=defaultdict(list)
    for row in fugu['rows']: groups[(row['cohort'],row['kind'])].append(row)
    order=[('mcptox','malicious'),('clean_descriptions','benign'),('crafted','malicious'),('crafted','benign'),('composition','malicious'),('composition','benign'),('reputation','vulnerable_dependency'),('reputation','dependency_control')]
    text_labels=['External attack descriptions','Constructed clean descriptions','Authored source attack fixtures','Authored source clean fixtures','Composition attacks','Composition controls · correctly unflagged','Pinned vulnerable dependency probe','Dependency control · OSV risk found']
    summary=[]
    for key in order:
        item={'cohort':key[0],'kind':key[1],**cohort_score(groups[key])}
        if key[0]=='composition':
            item['raw_rule_alerts']=item['flagged']
            item['correctly_unflagged']=(item['completed']-item['flagged']) if key[1]=='benign' else None
        summary.append(item)
    fig,ax=plt.subplots(figsize=(12,7));fig.subplots_adjust(left=.32,right=.96,top=.76,bottom=.22)
    fig.suptitle('Separate cohorts. Visible exclusions.',x=.07,y=.95,ha='left',fontsize=23,fontweight='bold')
    fig.text(.07,.87,f"{len(fugu['rows'])}/40 attempted cases · "+('after recovery · ' if recovered else '')+'medium+ findings · no pooled accuracy',fontsize=12)
    for i,item in enumerate(summary):
        flagged=item['flagged'];clear=item['completed']-flagged;excluded=item['excluded']
        ax.barh(i,flagged,color=teal,height=.55)
        ax.barh(i,clear,left=flagged,color='#d8dfe5',height=.55)
        ax.barh(i,excluded,left=flagged+clear,color=amber,height=.55)
        ax.text(item['attempted']+.25,i,cohort_annotation(item),va='center',fontsize=10)
    ax.set_yticks(range(len(order)),text_labels);ax.invert_yaxis();ax.set_xlim(0,max(s['attempted'] for s in summary)+8)
    ax.set_xlabel('Cases');fig.legend(handles=[plt.Rectangle((0,0),1,1,color=c) for c in (teal,'#d8dfe5',amber)],labels=['Flagged (completed)','Unflagged (completed)','Excluded / incomplete'],frameon=False,loc='lower center',bbox_to_anchor=(.5,.11),ncols=3,fontsize=10)
    fig.text(.07,.08,'Attack rows measure detections; controls show expected absence of a rule alert and preserve the raw count.',fontsize=10,color='#576b78')
    fig.text(.07,.04,'Amber = incomplete. Composition scores cross-extension rules; member alerts and overall verdicts remain separate.',fontsize=10,color='#576b78')
    save(fig,'cohort-results')
    contribution = contribution_data(fugu['rows'])
    fig,ax=plt.subplots(figsize=(12,7));fig.subplots_adjust(left=.31,right=.95,top=.76,bottom=.23)
    fig.suptitle('Which checks raised alerts?',x=.07,y=.95,ha='left',fontsize=23,fontweight='bold')
    fig.text(.07,.87,'Medium+ alerts / completed applicable stage exercises; findings overlap across checks',fontsize=12)
    stage_names=['concealment','static','semantic','detonation','harness','reputation','composition']
    matrix=np.full((len(order),len(stage_names)),np.nan)
    for i,key in enumerate(order):
        for j,name in enumerate(stage_names):
            cell=contribution.get('/'.join(key),{}).get(name,{})
            if cell.get('rate') is not None:matrix[i,j]=cell['rate']
    palette=plt.get_cmap('GnBu').copy();palette.set_bad('#e8edf1')
    ax.imshow(matrix,cmap=palette,vmin=0,vmax=1,aspect='auto')
    for i,key in enumerate(order):
        for j,name in enumerate(stage_names):
            cell=contribution.get('/'.join(key),{}).get(name,{})
            label=f"{cell['flagged']}/{cell['completed']}" if cell.get('completed') else '—'
            ax.text(j,i,label,ha='center',va='center',color='white' if matrix[i,j]>.6 else '#172b3a',fontsize=12)
    ax.set_yticks(range(len(order)),text_labels)
    ax.set_xticks(range(len(stage_names)),['Decode','Static','Semantic','Sandbox','A/B harness','Reputation','Composition'],rotation=30,ha='right')
    fig.text(.07,.09,'Dash = no completed applicable exercise. Composition member stages require all applicable member results to complete.',fontsize=10,color='#576b78')
    fig.text(.07,.045,'Alerts on control rows are flags, not successful detections. Sandbox alert counts do not imply every attack was activated.',fontsize=10,color='#576b78')
    save(fig,'stage-alerts')
    if recovered:
        initial=json.loads((source/'fugu.json').read_text())
        initial_valid=sum(r['complete'] for r in initial['rows'])
        final_valid=sum(r['complete'] for r in fugu['rows'])
        fig,ax=plt.subplots(figsize=(12,5));fig.subplots_adjust(left=.23,right=.95,top=.65,bottom=.29)
        fig.suptitle('Recovery improves completion. It does not fix the app.',x=.07,y=.93,ha='left',fontsize=21,fontweight='bold')
        totals=[len(initial['rows']),len(fugu['rows'])];valid=[initial_valid,final_valid]
        excluded=[n-v for n,v in zip(totals,valid)]
        ax.barh(range(2),valid,color=teal,height=.5,label='Completed applicable checks')
        ax.barh(range(2),excluded,left=valid,color=amber,height=.5,label='Incomplete / excluded')
        ax.set_yticks(range(2),['Initial execution','After bounded recovery']);ax.invert_yaxis();ax.set_xlim(0,45)
        for i,(v,n) in enumerate(zip(valid,totals)):ax.text(n+.5,i,f'{v}/{n}',va='center',fontsize=12)
        ax.set_xlabel('Frozen cases');ax.legend(loc='upper left',bbox_to_anchor=(0,-.2),frameon=False,ncols=2,fontsize=10)
        fig.text(.07,.09,'One identical-prompt retry only for missing A/B replies, with 4,096 output tokens. Every valid initial reply stays unchanged.',fontsize=10,color='#576b78')
        fig.text(.07,.04,'Original failures and all token usage remain in the evidence. Product source and its default output limits remain unchanged.',fontsize=10,color='#576b78')
        save(fig,'recovery-reliability')
    data={'comparison':comparison,'coverage':coverage,'cohorts':summary,'stage_contribution':contribution,'reporting':reporting}
    (charts/'chart-data.json').write_text(json.dumps(data,indent=2)+'\n')
    with (charts/'cohort-data.csv').open('w',newline='') as handle:
        fieldnames=list(dict.fromkeys(field for row in summary for field in row))
        writer=csv.DictWriter(handle,fieldnames=fieldnames);writer.writeheader();writer.writerows(summary)
    return data


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=DEFAULT_SOURCE,
                        help='frozen full-benchmark input directory')
    parser.add_argument('--out',type=Path,default=DEFAULT_OUTPUT,
                        help='new output directory; historical input files remain untouched')
    parser.add_argument('--bounds-only',action='store_true')
    parser.add_argument('--draft',action='store_true')
    parser.add_argument('--recovered',action='store_true')
    args=parser.parse_args()
    if args.bounds_only:
        manifest=json.loads((args.source/'cases.json').read_text())
        args.out.mkdir(parents=True,exist_ok=True)
        (args.out/'harness-mount-bounds.json').write_text(json.dumps(mount_bounds(args.source,manifest),indent=2)+'\n')
    else:
        data=render(args.source,output=args.out,draft=args.draft,recovered=args.recovered)
        print(json.dumps(data['comparison'],indent=2))


if __name__=='__main__': main()

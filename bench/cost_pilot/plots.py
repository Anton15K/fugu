"""Report-only Matplotlib renderer. Receives publishable JSON, never sources/keys."""
from __future__ import annotations
import argparse
import json
import math
import os
from pathlib import Path
from .contracts import SafetyStop
from .freeze import immutable_json


def chart_data(data):
    if data.get('schema_version')!=1:raise SafetyStop('chart_schema')
    rows=[];source=data.get('rows',data.get('cases',[]));identities=set()
    for r in source:
        identity=(r['case'],r['arm'])
        if identity in identities or r['arm'] not in {'agent','fugu'}:raise SafetyStop('chart_duplicate')
        identities.add(identity);workflow=r['workflow']
        if workflow not in {'complete','partial','failed','unattempted'}:raise SafetyStop('chart_workflow')
        if 'cost' in r:
            cost=r['cost'];lower=cost['known_micro']/1e6;upper=(cost['known_micro']+cost['unknown_upper_micro'])/1e6
            if workflow=='unattempted':
                if lower or upper:raise SafetyStop('chart_unattempted_cost')
                lower=upper=None
            tp=r.get('tp')
        else:lower=r.get('cost_lower_usd');upper=r.get('cost_upper_usd');tp=r.get('validated_tp')
        if workflow=='unattempted':
            if lower is not None or upper is not None or tp is not None:raise SafetyStop('chart_unattempted_cost')
        elif lower is not None or upper is not None:
            if any(type(x) not in {int,float} or not math.isfinite(x) or x<0 for x in (lower,upper)) or upper<lower:raise SafetyStop('chart_cost_bounds')
        if tp is not None and (type(tp) is not int or tp<0):raise SafetyStop('chart_tp')
        rows.append({'case':r['case'],'arm':r['arm'],'lane':r.get('lane','security'),'workflow':workflow,'cost_lower_usd':lower,'cost_upper_usd':upper,'validated_tp':tp,'decision_correct':r.get('decision_correct')})
    cases={r['case'] for r in rows};planned=data.get('planned_cases',len(cases))
    if type(planned) is not int or planned!=len(cases) or len(rows)!=2*planned:raise SafetyStop('chart_missing_planned_rows')
    return {'schema_version':1,'rows':rows,'planned_cases':planned,'unattempted_rows':sum(r['workflow']=='unattempted' for r in rows),'uncertain_rows':sum(r['workflow']!='unattempted' and (r['cost_lower_usd'] is None or r['cost_lower_usd']!=r['cost_upper_usd']) for r in rows),'caption':'Full product vs four-tool agent; Fugu-only OSV/Docker. Agent runtime observations structurally unavailable/zero. Estimated tariff USD; liability intervals are not measured usage. Single seed, small pilot.','omitted_points':[{'case':r['case'],'arm':r['arm'],'reason':'not measured' if r['workflow']=='unattempted' else 'cost or validated evidence unknown'} for r in rows if r['cost_lower_usd'] is None or r['validated_tp'] is None]}


def make_figures(chart):
    import matplotlib
    matplotlib.use('Agg')
    from matplotlib import pyplot as plt
    colors={'fugu':'#176a9a','agent':'#b66a18'};figures=[]
    for kind in ('correctness','case'):
        fig,axes=plt.subplots(1,2,figsize=(12,5),squeeze=False);figures.append(fig)
        for ax,lane in zip(axes[0],('security','functional')):
            rows=[r for r in chart['rows'] if r['lane']==lane];cases=sorted({r['case'] for r in rows})
            ax.set_title(f'{lane.title()} · {len(cases)} planned pairs',pad=26);ax.grid(axis='y',alpha=.2)
            if kind=='correctness':
                for arm in ('fugu','agent'):
                    selected=[r for r in rows if r['arm']==arm and r['cost_lower_usd'] is not None and r['validated_tp'] is not None]
                    for i,r in enumerate(selected):
                        mid=(r['cost_lower_usd']+r['cost_upper_usd'])/2;err=(r['cost_upper_usd']-r['cost_lower_usd'])/2
                        ax.errorbar(mid,r['validated_tp'],xerr=err,fmt='o' if r['workflow']=='complete' else 'x',capsize=4,color=colors[arm],label=arm if i==0 else None)
                ax.set_xlabel('Estimated tariff cost (USD), liability interval');ax.set_ylabel('Validated true positives (attempted view)')
            else:
                for arm_index,arm in enumerate(('fugu','agent')):
                    for r in [r for r in rows if r['arm']==arm]:
                        x=cases.index(r['case'])+(arm_index-.5)*.32
                        if r['cost_lower_usd'] is None:ax.text(x,0,'not measured',rotation=90,va='bottom',ha='center',fontsize=8);continue
                        lo=r['cost_lower_usd'];hi=r['cost_upper_usd']
                        ax.bar(x,lo,width=.30,color=colors[arm],alpha=.75,hatch='//' if r['workflow']!='complete' else None,label=arm if r['case']==cases[0] else None)
                        if hi>lo:ax.errorbar(x,lo,yerr=[[0],[hi-lo]],fmt='none',capsize=4,color=colors[arm])
                ax.set_xticks(range(len(cases)),cases,rotation=45,ha='right');ax.set_ylabel('Estimated tariff cost (USD)');ax.set_xlabel('Frozen cases; partial bars hatched')
            missing=sum(r['workflow']=='unattempted' for r in rows);complete=sum(r['workflow']=='complete' for r in rows)
            ax.text(.02,1.01,f'{complete}/{len(rows)} complete; {missing} not measured',transform=ax.transAxes,va='bottom',fontsize=9)
            handles,labels=ax.get_legend_handles_labels()
            if handles:ax.legend(handles,labels,loc='best')
        fig.suptitle('Cost versus adjudicated evidence' if kind=='correctness' else 'Paired per-case costs and coverage')
        fig.text(.02,.02,chart['caption'],fontsize=8,wrap=True);fig.subplots_adjust(bottom=.24,top=.84,wspace=.32)
    return figures


def plot_results(results_json,output):
    import matplotlib
    if matplotlib.__version__!='3.10.8':raise SafetyStop('renderer_version')
    chart=chart_data(json.loads(Path(results_json).read_bytes()));output=Path(output);output.mkdir(parents=True,exist_ok=True,mode=0o700)
    names=['cost-correctness.png','cost-correctness.pdf','per-case-cost.png','per-case-cost.pdf','chart-data.json']
    if any((output/n).exists() for n in names):raise SafetyStop('chart_output_exists')
    figures=make_figures(chart);paths=[]
    from matplotlib import pyplot as plt
    try:
        for fig,prefix in zip(figures,('cost-correctness','per-case-cost')):
            for ext in ('png','pdf'):
                path=output/(prefix+'.'+ext)
                with path.open('xb') as f:
                    os.chmod(path,0o600);fig.savefig(f,format=ext,dpi=180,bbox_inches='tight');f.flush();os.fsync(f.fileno())
                paths.append(path)
        immutable_json(output/'chart-data.json',chart);paths.append(output/'chart-data.json')
    finally:
        for fig in figures:plt.close(fig)
    return paths


def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--results',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args(argv)
    try:files=plot_results(a.results,a.output)
    except SafetyStop as exc:print(json.dumps({'status':'BLOCKED','reason':exc.reason}));return 2
    print(json.dumps({'status':'rendered','files':[str(f) for f in files]}));return 0

if __name__=='__main__':raise SystemExit(main())

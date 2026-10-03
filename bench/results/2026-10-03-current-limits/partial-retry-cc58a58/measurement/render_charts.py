"""Offline dated plots of the measured three-interval result; no provider imports."""
import copy
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT))
from bench import current_limits as base
from bench.current_limits_charts import comparison_data, load_competitors
from bench.current_limits_continuation_charts import _cohort_coverage

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
OUT = HERE / 'charts'
OUT.mkdir(exist_ok=True)
combined = base.read_json(HERE / 'combined.json')
original = base.read_json(base.FROZEN / 'cases.json')
prior = base.read_json(HERE.parent.parent / 'continuation-cc58a58-untouched' / 'combined.json')
assert combined['protocol'] == 'current-production-source-inference-partial-retry-v1'
assert len(combined['rows']) == 40 and [r['id'] for r in combined['rows']] == [c['id'] for c in original['cases']]
assert combined['limits']['llm_max_output_tokens'] == 4096
assert [i['id'] for i in combined['intervals']] == ['parent', 'child', 'retry']
assert sum(i['usage']['attempts'] for i in combined['intervals']) == combined['usage']['attempts'] == 1307
assert all(a == b for a, b in zip(combined['rows'], prior['rows']) if a['id'] != 'mcptox/AlphaVantage_4')
competitors = load_competitors(original, base.FROZEN / 'competitors')
comparison = comparison_data(combined, original, competitors)
adjudication = base.read_json(HERE.parent / 'prior-benign-adjudication.json')
assert adjudication['scored_benign_case_flags'] == 1
assert adjudication['independent_adjudications'][0]['id'] == 'clean/read_file'
assert 'false flag' in adjudication['independent_adjudications'][0]['independent_classification']
presentation = copy.deepcopy(comparison)
presentation['primary']['fugu'].update(confirmed_false_positives=1, pending_adjudication=0,
    adjudication_basis='Accepted independent reference; original raw null fields preserved')
cohorts = _cohort_coverage(combined['rows'])
data = dict(schema=1, protocol=combined['protocol'], synthetic=False,
    measured_utc=combined['measured_utc'], engine=combined['engine'], limits=combined['limits'],
    comparison=presentation, raw_field_comparison=comparison, cohorts=cohorts,
    intervals=combined['intervals'], usage=combined['usage'], coverage=combined['coverage'],
    lineage=combined['lineage'], prior_benign_adjudication=combined['prior_benign_adjudication'],
    result_sha256=base.sha((HERE/'combined.json').read_bytes()),
    case_manifest_sha256=base.sha((base.FROZEN/'cases.json').read_bytes()),
    comparator_sha256={name:base.sha((base.FROZEN/'competitors'/name).read_bytes())
                      for name in ('fuzzd.json','mcp-sec-audit.json','setup.json')},
    caveats=['Three dated intervals, including an explicitly selected whole-case retry; no blind 40-case rerun',
             'Historical comparator snapshot 2026-10-02; tool-specific thresholds and source-only adapters',
             'Source/inference completion; no auditee execution, detonation or live reputation',
             'Accepted benign source-classification judgment by reference; original raw fields unchanged',
             'Unknown prior HTTP500 usage keeps whole token totals null; no costs or population rates'])
base.write_json(OUT/'chart-data.json',data)
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,
                     'axes.spines.right':False,'svg.fonttype':'none','savefig.facecolor':'white'})
teal, grey, orange, blue = '#267d72','#c5ced4','#d49a3f','#547b9d'
caption = 'Fugu: three measured intervals on 3 October 2026 UTC; full chronology in report and chart data.\nEngine cc58a58; output cap 4,096; source/inference only.'

def save(fig, name):
    fig.savefig(OUT/(name+'.png'),dpi=180)
    svg=OUT/(name+'.svg');fig.savefig(svg)
    svg.write_text(''.join(line.rstrip()+'\n' for line in svg.read_text().splitlines()))
    plt.close(fig)

primary=presentation['primary']
labels=['Fugu current profile','fuzzd 0.13.0\nHistorical 2026-10-02','mcp-sec-audit 0.1.0\nHistorical 2026-10-02']
detected=[primary['fugu']['attack_detected']]+[primary[k]['attack_medium_positive'] for k in ('fuzzd','mcp-sec-audit')]
missed=[primary['fugu']['attack_missed']]+[primary[k]['completed_attacks']-primary[k]['attack_medium_positive'] for k in ('fuzzd','mcp-sec-audit')]
incomplete=[primary['fugu']['attack_incomplete'],0,0]
flags=[primary[k]['raw_benign_flags'] for k in ('fugu','fuzzd','mcp-sec-audit')]
fig,axes=plt.subplots(1,2,figsize=(13.8,7.4),gridspec_kw={'width_ratios':[1.45,1]})
fig.suptitle('Fixed description packets: 15 attacks and 5 clean controls',fontsize=15,y=.97)
left=[0,0,0]
for values,color,label in ((detected,teal,'Detected'),(missed,grey,'Missed'),(incomplete,orange,'Incomplete')):
    axes[0].barh(labels,values,left=left,color=color,label=label)
    for index,(start,value) in enumerate(zip(left,values)):
        if value: axes[0].text(start+value/2,index,str(value),ha='center',va='center',color='white' if color==teal else '#26333e')
    left=[a+b for a,b in zip(left,values)]
for index,value in enumerate(detected): axes[0].text(15.3,index,f'{value}/15 planned',va='center')
axes[0].set_xlim(0,19);axes[0].invert_yaxis();axes[0].set_xlabel('Planned attack cases; tool-specific medium thresholds')
axes[0].legend(loc='upper left',bbox_to_anchor=(0,-.16),ncol=3,fontsize=9)
axes[1].barh(labels,flags,color=blue);axes[1].invert_yaxis();axes[1].set_xlim(0,5)
for index,value in enumerate(flags): axes[1].text(value+.08,index,f'{value}/5 flags',va='center')
axes[1].set_xlabel('Flags on the fixed clean-description controls')
axes[1].set_title('Clean-description flags',fontsize=11)
fig.text(.04,.045,caption+'\nHistorical native capability flags: fuzzd 11/15; mcp-sec-audit 12/15. These differ from normalized detection.\n'
         'Adjudication details are linked in the report. No population rates, tool execution or universal ranking.',fontsize=9)
fig.subplots_adjust(left=.15,right=.97,top=.79,bottom=.30,wspace=.62)
save(fig,'common-results')

fig,ax=plt.subplots(figsize=(12,7))
labels=[f"{r['cohort']} / {r['kind']}" for r in cohorts]
ax.barh(labels,[r['completed'] for r in cohorts],color=teal)
for index,r in enumerate(cohorts): ax.text(r['completed']+.15,index,f"{r['completed']}/{r['planned']}",va='center')
ax.invert_yaxis();ax.set_xlim(0,18);ax.set_xlabel('Completed source/inference cases / planned cases')
fig.suptitle('40/40 cases complete across three measured intervals',fontsize=15,y=.97)
fig.text(.04,.055,caption+'\nAll 18 mounted comparisons in the fresh whole-case retry completed; aggregate coverage is 792/792.\n'
         'Dependency reputation outcomes remain unavailable; source/inference completion is a separate measure.',fontsize=9)
fig.subplots_adjust(left=.35,right=.95,top=.87,bottom=.25)
save(fig,'cohort-coverage')

intervals=combined['intervals'];fig,axes=plt.subplots(1,3,figsize=(13.8,6.5))
fig.suptitle('Actual SDK accounting: original, continuation and whole-case retry',fontsize=15,y=.97)
for ax,(key,title) in zip(axes,[('attempts','SDK attempts'),('completion_tokens_known_subtotal','Known completion tokens'),('sum_request_duration_s','Summed SDK seconds')]):
    vals=[i['usage'][key] for i in intervals];ax.bar(['Original','Continuation','Retry'],vals,color=[orange,teal,blue])
    for index,value in enumerate(vals): ax.text(index,value,f'{value:,.2f}' if isinstance(value,float) else f'{value:,}',ha='center',va='bottom',fontsize=9)
    ax.set_title(title);ax.margins(y=.18);ax.tick_params(axis='x',labelrotation=15)
fig.text(.04,.05,caption+'\nTotal 1,307 SDK attempts: 359 + 919 + 29. Original HTTP500 remains recorded; retry had zero provider/native errors.\n'
         'Retry tokens: 6,724 prompt + 7,636 completion. Combined known subtotals: 590,135 + 427,925; whole totals unknown.\n'
         'Costs and remaining quota unmeasured. SDK duration sums exclude gaps between the three intervals.',fontsize=9)
fig.subplots_adjust(left=.07,right=.98,top=.84,bottom=.32,wspace=.42)
save(fig,'call-telemetry')
print({'plots':3,'provider_requests':0,'result_sha256':data['result_sha256'],'comparison':presentation['primary']['fugu']})

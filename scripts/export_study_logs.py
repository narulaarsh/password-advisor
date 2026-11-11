"""E4 participant-clustered summaries. Demo/synthetic rows never count as human evidence."""
import argparse,csv,json
from pathlib import Path
import numpy as np

def export_study_summary(input_csv='data/private/study_events.csv', output_csv='results/review1/study_summary.json', source='human',
                         questionnaire_csv=None):
    with open(input_csv,newline='') as f:rows=list(csv.DictReader(f))
    if any('source' not in r or 'vulnerable' not in r for r in rows):
        raise ValueError('Legacy logs lack independent outcome/provenance; cannot establish the E4 primary outcome')
    rows=[r for r in rows if r['source']==source]
    if not rows:raise ValueError(f'No {source} observations; no result can be reported')
    seen=set();assignment={}
    for r in rows:
        key=(r['participant_id'],r['task_id'])
        if key in seen:raise ValueError('Duplicate participant-task observation; adjudicate before analysis')
        seen.add(key)
        if r['participant_id'] in assignment and assignment[r['participant_id']]!=r['condition']:
            raise ValueError('Participant assigned to multiple conditions')
        assignment[r['participant_id']]=r['condition']
    rng=np.random.default_rng(42);summary={};samples={}
    for condition in ('G1','G2','G3','G4'):
        sub=[r for r in rows if r['condition']==condition]
        ids=sorted({r['participant_id'] for r in sub})
        rates=[]
        for pid in ids:
            vals=[int(r['vulnerable']) for r in sub if r['participant_id']==pid and r['vulnerable'] in ('0','1')]
            if vals:rates.append(float(np.mean(vals)))
        boot=np.array([np.mean(rng.choice(rates,len(rates),replace=True)) for _ in range(2000)]) if rates else None
        samples[condition]=boot
        warnings=sum(int(r['warning_shown']) for r in sub)
        summary[condition]=dict(participants=len(ids),tasks=len(sub),labelled_tasks=sum(r['vulnerable'] in ('0','1') for r in sub),
                 participant_mean_vulnerable_rate=float(np.mean(rates)) if rates else None,
                 cluster_bootstrap_ci95=np.percentile(boot,[2.5,97.5]).tolist() if boot is not None else None,
                 override_rate=sum(int(r['overridden']) for r in sub)/warnings if warnings else None,
                 adoption_rate=sum(int(r['accepted_alternative']) for r in sub)/warnings if warnings else None,
                 median_time_ms=float(np.median([float(r['time_ms']) for r in sub])) if sub else None)
    contrasts={}
    for left,right in [('G3','G2'),('G4','G3'),('G4','G1')]:
        if samples[left] is not None and samples[right] is not None:
            contrasts[f'{left}_minus_{right}']=dict(difference=summary[left]['participant_mean_vulnerable_rate']-summary[right]['participant_mean_vulnerable_rate'],ci95=np.percentile(samples[left]-samples[right],[2.5,97.5]).tolist())
    usability={}
    if questionnaire_csv:
        with open(questionnaire_csv,newline='') as f:q=[r for r in csv.DictReader(f) if r.get('source')==source]
        if len({r['participant_id'] for r in q})!=len(q):raise ValueError('Duplicate questionnaire per participant')
        for r in q:
            if assignment.get(r['participant_id']) not in (None,r['condition']):raise ValueError('Questionnaire condition differs from task condition')
        qrng=np.random.default_rng(7)
        for condition in ('G1','G2','G3','G4'):
            scores=[float(r['sus_score']) for r in q if r['condition']==condition]
            boot=[np.mean(qrng.choice(scores,len(scores),replace=True)) for _ in range(2000)] if scores else None
            usability[condition]=dict(participants=len(scores),mean_sus=float(np.mean(scores)) if scores else None,
                                      bootstrap_ci95=np.percentile(boot,[2.5,97.5]).tolist() if boot else None)
    report=dict(source=source,estimand='Equal-participant mean retained vulnerability rate',groups=summary,contrasts=contrasts,usability_sus=usability,
                limitations=['Primary label relative to specified attacker/budget only','Bootstrap inference is unstable with few participants','No study power or external validity established by this analysis'])
    out=Path(output_csv);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2))
    return report
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',default='data/private/study_events.csv');p.add_argument('--output',default='results/review1/study_summary.json');p.add_argument('--source',choices=['human','demo','synthetic'],default='human');p.add_argument('--questionnaire',default=None);a=p.parse_args()
    export_study_summary(a.input,a.output,a.source,a.questionnaire)

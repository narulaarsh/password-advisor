# Study protocol: save-time password feedback (G1–G4)

Draft for submission to [institution ethics committee]. Items in [brackets] must be completed by the investigators. No participant has been recruited.

## 1. Investigators and approval

- Principal investigator: [name, role, email]
- Investigators: Jasmeet Ranjan Srivastava, Garvit Singla, Rakshit Kapoor (Department of Computer Science and Engineering (Information Security), Vellore Institute of Technology)
- Ethics reference: [to be issued by the committee]. The study software refuses human-mode collection until this reference is configured (`STUDY_ETHICS_REFERENCE`).

## 2. Aim and hypotheses

**Aim.** Test whether the timing of password feedback changes the final credentials people keep, and whether offering an alternative adds to that effect.

- **H1.** Feedback shown before saving (G3) leads to fewer vulnerable final credentials than the same feedback shown after saving (G2).
- **H2.** Adding an immediately usable alternative (G4) reduces vulnerable credentials compared with G3.
- **H3 (secondary).** G4 compared with structural-only feedback (G1).

## 3. Design

- **Design.** Four-arm between-subjects experiment.
  - **G1:** structural feedback only.
  - **G2:** contextual feedback after the fictional credential is saved, with the warning kept until the participant edits or keeps it.
  - **G3:** the same contextual feedback before saving.
  - **G4:** G3 plus a locally generated alternative.
- **Allocation.** A concealed permuted-block schedule (blocks of 4) is created with `scripts/make_allocation_schedule.py` by a person who does not recruit. Participants receive slot IDs in enrollment order.
- **Task order.** The order of the three tasks is counterbalanced within each arm.
- **Tasks.** Three fictional tasks (a shop, an email service, a social account) using one fictional profile (Maya Carter, Denver, 1998) and a fictional previous password. Participants never use or reveal their own passwords.
- **Duration.** About [15] minutes, to be confirmed in a pilot.

## 4. Participants

- **Inclusion.** Adults aged 18 or over who are able to use a web browser. [Recruitment population, for example students and staff at the institution.]
- **Exclusion.** None beyond the inclusion criteria; participants who are under 18 or do not consent cannot start.
- **Sample size.** The simulation (`results/review2/power.json`) gives the participants needed per arm for 80% power on G3 against G2. These are planning assumptions, not data.

| Absolute reduction | Within-participant correlation 0.2 | Within-participant correlation 0.4 |
|---|---:|---:|
| 0.20 | 60 per arm (240 total) | 80 per arm (320 total) |
| 0.15 | 110 per arm (440 total) | 140 per arm (560 total) |
| 0.10 | 240 per arm (960 total) | 310–320 per arm (1,240–1,280 total) |

  These assume a control rate of 0.5–0.6. Choose the target effect before recruitment: [chosen effect and N], plus [x]% for dropout.

## 5. Outcomes

- **Primary.** The participant-level share of final fictional credentials that the prespecified offline attacker (S5) recovers within 1,000 guesses. The share is computed automatically and independently of the warning rules.
- **Secondary.** Override rate, acceptance of the alternative, total task time, and System Usability Scale score (Brooke, 1996).
- **Optional, if approved.** Comprehension of the warning, and delayed recall of the final credential after [x] days.

## 6. Analysis plan (to be preregistered)

The analysis uses participant-level rates, with clustered bootstrap 95% intervals. The contrasts are G3 − G2 (primary), G4 − G3 and G4 − G1, with Bonferroni-adjusted alpha = 0.05/3 (`scripts/export_study_logs.py`). Only records labelled `human` are analysed. Duplicate participant-task records and inconsistent assignments are rejected.

## 7. Risks and mitigations

- **Disclosure of real passwords.** The tasks use a fictional profile; the consent text and on-screen instructions forbid real passwords; and no password or password hash is stored.
- **Identifiability.** Only pseudonymous slot IDs are used. The slot-to-person mapping, if one is kept at all, is held separately by [coordinator] and destroyed after [date].
- **Burden.** About 15 minutes, with no deception. Participants can stop at any time.

## 8. Data management

- **Stored data.** The event log (`data/private/study_events.csv`, mode 0600) holds the slot ID, condition, task, task position and order, whether a warning was shown, override, alternative accepted, decision time, the attacker outcome, source label, protocol ID and timestamp. The questionnaire log holds the slot ID, condition, ten SUS answers, SUS score, source label, protocol ID and timestamp.
- **Not stored.** Names, contact details, passwords, password hashes or IP addresses.
- **Storage and retention.** [Encrypted institutional storage]. Data are kept for [x years] and then deleted.
- **Withdrawal.** A participant can withdraw before [date or analysis lock]; all rows with their slot ID are then deleted.
- **Sharing.** Only aggregated results are published. [Whether de-identified logs will be shared.]

## 9. Before recruitment

1. Obtain the ethics reference, then set `STUDY_MODE=1`, `STUDY_ETHICS_REFERENCE` and `STUDY_ALLOCATION_FILE`.
2. Run a small pilot to confirm timing and clarity. Pilot data are labelled `synthetic` or kept apart and are never pooled with main-study data.
3. Freeze the analysis plan, the effect size and N, and register them [registry].

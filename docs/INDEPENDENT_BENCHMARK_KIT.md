# Independent benchmark kit (Review 2, P0 item E1/E2)

The review asks for a benchmark that is independent of the people who built CAV. This kit lets other people create it and run the existing analysis on it unchanged. The CAV authors must not write, label or tune any part of it.

## Roles

| Role | Who | Must not |
|---|---|---|
| Coordinator | A faculty member or a person outside the project | Share CAV source code or detector rules with authors or annotators |
| Authors (3 or more) | People not involved in CAV | See CAV, its fixture or its results |
| Annotators A and B | Two people not involved in CAV, working separately | Discuss labels before both have finished |
| Adjudicator | A third person, not an author or annotator | Change labels that A and B agreed on |

## Step 1: author fictional profiles and passwords

Use only invented people. Do not base any profile on a real person or use a real password.

1. **Profiles.** Each author writes 30 or more fictional profiles: first name, surname, city and birth year. Use names from several languages and scripts, including names with accents, apostrophes and hyphens and names written in their native script.
2. **Passwords.** For each profile, write 6–12 passwords as a real person might. Include some built from the profile, using any transformation you think people use, and some unrelated to it. Also write one earlier password for each profile, and some later passwords derived from it.
3. **Scope.** No author sees CAV, its documentation or the synthetic fixture.

Record each item as one JSON line, using the contract in `REVIEW1_PROTOCOL.md`:

```json
{"id":"A1-007","profile_id":"A1-P03","family_id":"A1-P03","template_id":"A1-free","split":"","profile":{"first_name":"Ilse","surname":"Van der Berg","city":"Gent","birth_year":1987},"password":"<authored>","previous_password":"<authored>","other_passwords":["<authored>"],"label_personal":0,"breach_count":0,"age_days":30,"criticality":2,"category":"","provenance":"authored by A1 for the CAV independent benchmark, <date>"}
```

`breach_count` must come from a real lookup made at authoring time, or be 0 for invented strings that are not checked. Never make it up.

## Step 2: assign splits before labelling

The coordinator assigns whole profiles to `train`, `validation` and `test`, in roughly 40/20/40 proportions. Every author's profiles are spread across all three splits. `template_id` is the author ID plus `-free`, so the validator also blocks leakage between authors. The test split is then sealed and must not be inspected until the final run.

## Step 3: label independently

Each annotator fills in a CSV (`id,label_personal,category`) for every item, without seeing the other annotator's file:

- `label_personal = 1` if the password contains or is derived from any declared profile attribute, in any form: shortened, reordered, transliterated, with accents removed, in leetspeak or combined with other text. Otherwise 0.
- `category` is a free-text description of the transformation, such as "diacritics removed" or "name reversed".

## Step 4: agreement and adjudication

```sh
.venv/bin/python scripts/benchmark_agreement.py --items items.jsonl --annotator-a a.csv --annotator-b b.csv
```

Report Cohen's kappa. If kappa is below 0.6, revise the labelling guide and relabel a fresh sample before continuing. The adjudicator labels only the disagreements (`adjudication.csv`), and then:

```sh
.venv/bin/python scripts/benchmark_agreement.py --items items.jsonl --annotator-a a.csv --annotator-b b.csv \
    --adjudication adjudication.csv --out data/private/independent_benchmark.jsonl
```

The output is checked by the same validator as the synthetic fixture: explicit splits, no profile, family, template or password shared between splits, binary labels and stated provenance.

## Step 5: run the unchanged analysis

```sh
.venv/bin/python scripts/review2_experiments.py --input data/private/independent_benchmark.jsonl --out results/review3-independent
```

Do not change the detector, weights or thresholds after looking at the test split. Report results whether they are favourable or not, together with the kappa, the number of authors and annotators, and the provenance statement. Keep the benchmark private (`data/private/` is ignored by git).

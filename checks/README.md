# checks/

One YAML file per KSI. Each file is the check definition: what to query, how often, the rule that decides true / false / null, and the wording of the result. `schema.json` is the JSON Schema those files must satisfy.

## Who owns what

| Part | Owner | Why |
|---|---|---|
| `evaluate.pass_when`, `evaluate.null_when`, `evaluate.parameters`, `rationale` | Compliance | Deciding what counts as "met" is a FedRAMP interpretation. Changing it is a reviewed change to this file, not a code change. |
| The collector that runs `source.query` against the real system | Engineering | Only the team that runs the system knows how to authenticate to it, page through it, and handle its errors. |

Engineering does not edit the rule. Compliance does not write the API client. The check file is the contract between them.

## Collector contract

- Emit exactly one record per check per `collect.interval`. Every record must validate against `../schema/ksi-evidence.schema.json`.
- Set `next_collection_due` to `collected_at` plus `collect.interval`.
- When collection fails for any reason (error, timeout after `collect.timeout`, unexpected response shape, or any case listed in `null_when`), still emit the record, with `result: null` and the `null` rationale template filled with `{failure_reason}`. A missing record is never acceptable; a null record is the finding.
- Fill the `pass` or `fail` template with the placeholders listed at the top of each check file. Do not write free-form rationale.

`../collector.py` is a reference implementation of this contract.

## Validate

```bash
python validate.py --checks
```

# Writing a check

A check turns a KSI statement into a rule a machine can apply. The rule is `pass_when`. Everything else in the check file supports it.

This guide covers how to get from the statement to the rule, the three ways it usually goes wrong, and a blank template.

## From statement to rule

Work through these steps in order.

1. **Copy the statement verbatim.** Paste it from fedramp.gov into `statement`. Do not paraphrase. The rule has to answer this text, not your memory of it.
2. **Name the claim.** Ask what observable fact would show the statement is true. For KSI-IAM-APM the statement talks about phishing-resistant authentication. The observable fact is the list of methods each policy permits.
3. **Name the scope.** Which things must the fact hold for? All policies? Only in-scope ones? Who decides what is in scope? Write that down. It becomes one of your extractions.
4. **Write the rule as a set or count comparison.** Good rules read like "every X is in Y", "set A equals set B", or "count of Z is at least 1". If you cannot phrase it that way, the claim is probably still too vague.
5. **Write the null branch.** List every way the evidence could be missing or unusable. Each one gives null, never true.
6. **Write the three rationale templates.** Pass, fail, and null. Use `{placeholders}` for anything the data supplies.

Here is what that produced for KSI-IAM-APM, from `checks/ksi-iam-apm.yaml`:

```yaml
pass_when: >-
  Every value in permitted_methods is a member of allowed_methods
  {fido2, piv, passkey}. Comparison is exact on lowercased method
  identifiers, so an unrecognized identifier fails rather than passes.
```

## The three traps

### Trap 1: too loose

The rule passes almost any configuration.

- Example: "MFA is enabled on all policies." A policy that accepts SMS codes passes. The KSI asks for phishing-resistant methods, so this rule is checking a different, easier thing.
- Example: "The inventory API returned resources." Any non-empty response passes. Nothing is compared to anything.
- How to spot it: describe a setup you know is non-compliant. Walk it through the rule. If it passes, the rule is too loose.

### Trap 2: too tight

The rule encodes one product's settings, field names, or defaults.

- Example: "The policy's `assurance_level` field equals `AAL3_HARDWARE`." That only works for a product that has that exact field. It breaks the day the product changes, and it says nothing a reviewer can check against the KSI.
- Example: "Exactly these six log sources report." A new log source would fail the check even though nothing is wrong.
- How to spot it: ask whether the rule would still make sense if the team switched to a different identity provider or cloud API tomorrow. If not, move the product detail into the collector and keep the rule in generic terms. The collector translates product fields into the names the rule uses.

### Trap 3: forgetting the null branch

The rule says when to pass. Everything else falls through to false, or worse, to true.

- Example: the API returns an empty list. "Every policy is phishing-resistant" is technically true of zero policies. Without a null branch, an outage or a permissions error looks like a pass.
- Example: the API times out and the collector writes nothing. A missing record is invisible. A null record is a finding.
- How to spot it: for each extraction, ask "what if this is empty, missing, or the call fails?" Each answer should appear in `null_when`.

## Questions to ask the engineer before filling in source.query

Ask these before you write the query. The answers often change it.

1. **What is the authoritative system for this data?** Not a dashboard, a cache, or a nightly copy. The system that actually enforces or records it.
2. **Does it have an API that returns this data?** If the answer is "only in the admin console", you need a different source or a manual exception.
3. **Can a service account get read access to it?** Read only. If collecting evidence needs write or admin access, that is a problem to solve first.
4. **How often does the data change?** This sets `collect.interval`. Data that changes hourly should not be checked weekly.
5. **What does failure look like?** Error codes, timeouts, rate limits, partial pages. Each one should become a null record. This also tells you what to put in `collect.timeout`.
6. **Does the response say what is in scope, or do we need a second source for that?** Scope often lives in the asset inventory, not the system being checked.

## Blank check template

Copy this into `checks/ksi-xxx-yyy.yaml` and fill it in. It matches `checks/schema.json`. Run `python validate.py` with the checks flag to confirm it is well formed.

```yaml
# Check definition for KSI-XXX-YYY. Owned by compliance.
#
# Rationale placeholders filled by the evaluation step:
#   example_count     (describe each placeholder the templates use)
#   failure_reason    why collection or evaluation could not complete

# KSI identifier exactly as published by FedRAMP.
ksi_id: KSI-XXX-YYY

# The KSI statement copied verbatim from fedramp.gov. Do not paraphrase.
statement: ""

# 20x class this check is evaluated against: A, B, or C.
class: B

# Accountable team or role. Never a person's name.
owner: ""

# How the evidence is obtained: api_query, config_export, log_query, or manual.
evidence_type: api_query

source:
  # Logical name of the authoritative system, in generic terms.
  # Examples: identity-provider, iac-state, siem, asset-inventory.
  system: ""
  # The call or query, in enough detail that someone else could re-run it.
  # Agree this with the engineer before you finalize it.
  query: ""

collect:
  # How often a record must be produced. ISO 8601 duration, for example PT24H.
  interval: PT24H
  # How long the fetch may run before the collector gives up and writes null.
  timeout: PT5M

evaluate:
  # Optional. Constants the rule refers to by name, such as an allowed set.
  # Keeping them here means changing them is a reviewed change to this file.
  parameters:
    example_allowed_values: []

  # Named values to pull from the response. pass_when refers to these names.
  # jsonpath is optional; description is required and must be precise
  # enough for an engineer to implement without asking you.
  extract:
    - name: example_items
      jsonpath: "$.items[*]"
      description: ""

  # Plain English: (write the rule here in one sentence)
  # The rule for result true. Phrase it as a set or count comparison.
  pass_when: >-

  # Every condition that makes the result null instead of true or false.
  # Always include fetch errors and timeouts. Include empty scope.
  null_when: >-

rationale:
  # Rendered when result is true. Say what the data showed.
  pass: ""
  # Rendered when result is false. Name what failed and where.
  fail: ""
  # Rendered when result is null. Must contain {failure_reason}.
  # Quote the key: unquoted, YAML reads null as "no value", not the word.
  "null": "{failure_reason}. No evidence could be gathered. Treated as a finding under VDR-CSO-FAV: a failure of the detection process is itself a vulnerability, not a skipped check."

# SP 800-53 Rev 5 controls FedRAMP maps to this KSI, copied from fedramp.gov.
# Lowercase, enhancements as parent.enhancement (ia-2.1).
related_800_53_controls: []
```

## Before you hand it over

- Walk one compliant and one non-compliant setup through `pass_when` on paper. The first should pass and the second should fail.
- Walk an empty response through it. It should be null.
- Check that every `{placeholder}` in the templates is listed in the comment block at the top, so the engineer knows to fill it.

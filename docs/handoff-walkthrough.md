# Handoff walkthrough: KSI-IAM-APM

This is one KSI taken from a blank page to a record that runs every day. It is written as the conversation a compliance SME and an engineer would actually have. The files it refers to are real: `checks/ksi-iam-apm.yaml`, `collector.py`, and `samples/ksi-iam-apm-pass.json`.

The people:

- **Compliance**: owns the FedRAMP interpretation. Knows what KSI-IAM-APM requires. Does not write code.
- **Engineer**: on the identity engineering team. Knows the identity provider. Will write and run the collector.

## 1. Compliance hands over the check

**Compliance:** Here is `checks/ksi-iam-apm.yaml`. It is the definition for KSI-IAM-APM. The part I need you to read closely is `pass_when`.

**Compliance:** In one sentence: the check passes only if every authentication method that any in-scope policy allows is FIDO2, PIV, or a passkey. Not most of them. Every one, across every in-scope policy.

**Engineer:** And if there are no in-scope policies?

**Compliance:** Then the result is null, not true. That is in `null_when`. An empty scope proves nothing, so it cannot pass.

**Engineer:** What do you need from me?

**Compliance:** A collector. It runs on a schedule, once every 24 hours per `collect.interval`. It calls your identity provider, pulls the policies, and writes one record per run. The record must validate against the schema. If the call fails, you still write a record, with `result: null`.

## 2. The engineer pushes back on the query

**Engineer:** The `source.query` assumes one call returns each policy with a list of permitted methods. Our identity provider does not work that way.

**Engineer:** Policies point at "authenticator groups" by ID. The groups list the factor types. So it is two calls and a join. There is also a simpler endpoint that returns `mfa_required: true` per policy. Can I just use that?

**Compliance:** No. That endpoint answers "is MFA on?" The KSI asks a different question: "is every factor a user could use phishing-resistant?"

**Compliance:** A policy that requires MFA but accepts SMS codes has `mfa_required: true`. It still fails KSI-IAM-APM. So that field cannot be the evidence.

**Engineer:** Fine. Then I will do the two calls and the join. For each in-scope policy I will resolve its groups and emit the full list of factor types that policy allows.

**Compliance:** That works. Whatever you call, the output has to prove one thing: the complete set of factors each in-scope policy permits. If a factor could be used to sign in and it is missing from your list, the evidence is wrong.

**Compliance:** I will update `source.query` in the check to describe your two calls and the join. That is a reviewed change to the check file. `pass_when` does not change. The rule is the same; only how we fetch the data changed.

## 3. The engineer ships a collector

**Engineer:** Done. I copied `collector.py` and replaced the fake fetch with a real one. It calls the policy endpoint, then the group endpoint, joins them, and maps each factor type to the lowercase names the check expects. It stores the raw responses in the evidence store and puts the hash and URI on the record.

**Engineer:** First record is back. Result is true.

```json
"result": true,
"rationale": "All 5 authentication policies in scope enforce phishing-resistant MFA (FIDO2 or PIV). No exceptions or legacy factors found."
```

## 4. Compliance reads the artifact, not the rationale

The rationale reads well. That is the problem. The rationale is generated from the collector's own view of the data. If the collector misread the data, the rationale repeats the mistake with confidence.

So compliance opens the raw artifact at `source.artifact_uri` and reads the five policies by hand.

**Compliance:** Policy `contractor-remote` allows one authenticator group. That group has a single factor of type `hardware_token`, and its settings say `"otp_mode": "totp"`. That is a key fob that shows a six-digit code. It is not phishing-resistant. Why did this pass?

**Engineer:** My mapping sent `hardware_token` to `fido2`. I assumed "hardware" meant a security key.

**Compliance:** So a TOTP-only policy was counted as FIDO2. The check never saw the word "totp".

**Engineer:** Right. The rule was fine. My translation fed it the wrong word.

## 5. The fix

**Engineer:** New mapping. Only factor types I can positively identify as FIDO2, PIV, or passkey get those names. Everything else passes through as its raw type, lowercased. So `hardware_token` with TOTP now arrives as `hardware_token_totp`.

**Compliance:** Good. That matches the check. It says an unrecognized identifier fails rather than passes. Unknown should always land on the failing side.

**Engineer:** Re-ran it. Result is now false.

```json
"result": false,
"rationale": "1 of 5 authentication policies in scope permit methods outside the phishing-resistant set (FIDO2, PIV, passkey): contractor-remote permits hardware_token_totp."
```

**Compliance:** That is the correct answer. It opens a ticket to `identity-engineering`. Either `contractor-remote` moves to a phishing-resistant factor, or someone files a deviation. The deviation is a separate reviewed record. Nobody edits this record to make it pass.

**Engineer:** I will also add a test with a fake response that contains a TOTP fob, so this mapping cannot quietly regress.

Two weeks later the contractor policy moves to FIDO2 keys. The next record is true, and this time the artifact agrees.

## 6. The day the API is down

On a later morning the scheduler runs the collector and the identity provider's policy API returns HTTP 503 on every retry until the five minute timeout in `collect.timeout` runs out.

The collector does not crash and does not skip the run. It writes this:

```json
"result": null,
"rationale": "Identity provider policy API returned HTTP 503 on every retry until the PT5M timeout. No evidence could be gathered. Treated as a finding under VDR-CSO-FAV: a failure of the detection process is itself a vulnerability, not a skipped check."
```

**Compliance:** That is exactly right. No data, no claim. The null opens a ticket to the owner like a false would. The next scheduled run will try again, and a true record later does not erase this one. The gap in evidence stays on the record.

## What each side owned

Compliance owned:

- The check file: `pass_when`, `null_when`, the parameters, and the rationale wording.
- Deciding whether a proposed query actually proves the KSI.
- Reading the first records against the raw artifact.

Engineering owned:

- The collector: authentication, the API calls, the join, the factor mapping.
- Storing the raw artifact and hashing it.
- Making sure every failure becomes a null record.
- Tests that pin down the mapping.

## What each side should never do

- **Compliance never writes the collector.** If the rule needs to change, change the check file. If the query needs to change, describe what it must prove and let engineering build it.
- **Engineering never reinterprets the KSI.** If the data does not fit the rule, raise it. Do not swap in an easier question ("is MFA on?") and do not map unknown values to passing ones.
- **Neither side edits a record after the fact.** A wrong result is fixed by fixing the collector or filing a deviation. The record stays as it was produced.

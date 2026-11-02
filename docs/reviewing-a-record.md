# Reviewing a record

Use this on the first record an engineer sends back for a new check. Every answer should be yes. One no means the collector is not ready to run on a schedule.

Have three things open: the record, the check file in `checks/`, and the raw artifact at `source.artifact_uri`.

## Checklist

1. **Does the query hit the authoritative system, not a cache or a copy?**
   Ask the engineer where the data comes from. A dashboard export, a nightly replica, or a search index of the real system is not the authoritative system.

2. **Is `source.artifact_sha256` present, and does it match the stored artifact?**
   Download the artifact and hash it (`shasum -a 256 <file>` or `sha256sum <file>`, depending on the machine). The value must match the record exactly. Ask the engineer to confirm the hash was taken over the exact bytes they stored, not a reformatted copy.

3. **Does the raw artifact support the result when you check it by hand?**
   Pick at least one item in the artifact and trace it through `pass_when` yourself. Do not rely on the rationale. The rationale is written from the collector's view of the data, so it repeats the collector's mistakes. See section 4 of `handoff-walkthrough.md`.

4. **Does the rationale state what the data showed, rather than restating the KSI?**
   Good: "All 4 authentication policies in scope enforce phishing-resistant MFA (FIDO2 or PIV)." Bad: "Phishing-resistant MFA is used." The first has a count and names the methods found. The second could be written without looking at anything.

5. **Would the record still be true if re-run now?**
   Ask the engineer to run the collector again while you watch. The result should be the same unless something actually changed. If it flips, find out why before accepting either record.

6. **Is the null case handled rather than crashing?**
   Ask the engineer to force a failure: a bad credential, a wrong URL, or a short timeout. You should get a schema-valid record with `result: null` and the null rationale filled in. A stack trace or no record at all is a no.

7. **Is `owner` a role or team, not a person?**
   `identity-engineering` is right. A person's name or email is not. People change jobs; the ticket still needs somewhere to go.

8. **Is `collected_at` in UTC?**
   It should end in `Z`, for example `2026-11-01T06:00:00Z`. A local time or an offset like `-05:00` is a no.

9. **Do `related_800_53_controls` match the fedramp.gov mapping for this KSI?**
   Compare against the KSI reference page, not against another record. The list should be copied from the check file, which was copied from fedramp.gov.

10. **Does `python validate.py` accept the record, and is `next_collection_due` equal to `collected_at` plus the check's `collect.interval`?**
    The validator catches shape errors. The due date tells you the collector read the interval from the check rather than hard-coding its own.

## What to do if it fails review

- **Write down which question failed and what you saw.** Quote the field or the line in the artifact. "Q3: policy `contractor-remote` allows a TOTP factor, but the result is true."
- **Send it back to the engineer as a collector bug.** Do not edit the record. Do not change `pass_when` to make the record correct, unless you find the rule itself was wrong.
- **If the rule was wrong, fix the check file first.** That is a reviewed change to `checks/`. Then the engineer re-runs the collector against the new check.
- **Ask for a test.** Whatever the bug was, the engineer should add a fixture that reproduces it, so it cannot come back unnoticed.
- **Review the next record from scratch.** Run the whole checklist again. A fix in one place can break another.
- **Do not let the collector go on the schedule until all ten are yes.** Records produced before then are not evidence.

# Glossary

Terms engineers will use when you hand them a check. Each has a plain definition and a sentence you might hear in a meeting.

**JSONPath**
A short expression that points at a value inside a JSON response, like a file path for data.
*"The JSONPath `$.policies[*].permitted_methods` pulls every method list out of the policy response."*

**Idempotent**
Running it twice gives the same result as running it once, with no extra side effects.
*"The collector is idempotent, so if the scheduler retries it we don't get duplicate tickets."*

**Exit code**
The number a program returns when it finishes. Zero means success. Anything else means something went wrong.
*"`validate.py` exits non-zero when a record is malformed, so the pipeline stops there."*

**CI (continuous integration)**
An automated system that runs checks every time someone pushes a code change.
*"CI runs the validator on every pull request, so a broken check file can't be merged."*

**Pipeline**
A sequence of automated steps that run one after another, where each step can stop the rest.
*"The evidence pipeline is collect, validate, store, then open a ticket if the result isn't true."*

**Artifact**
The raw output a process produced and kept, such as the exact API response the collector received.
*"Don't trust the rationale. Open the artifact and look at what the API actually returned."*

**Hash**
A fixed-length fingerprint of a file. Change one character in the file and the hash changes completely.
*"The record carries the SHA-256 hash of the artifact, so we can prove the file wasn't edited later."*

**Drift**
When what is actually running no longer matches what the configuration says should be running.
*"Eleven instances exist in the cloud API but not in IaC state. That's drift."*

**Null vs false**
False means the evidence was collected and shows the KSI is not met. Null means the evidence could not be collected or evaluated at all.
*"It's not false, it's null. The SIEM was down, so we have no idea whether logging was working."*

**Scheduler**
The system that starts jobs automatically at set times or intervals.
*"The scheduler kicks off the identity collector every 24 hours at 06:00 UTC."*

**Fixture**
A saved, known input used in a test, so the test gives the same answer every time.
*"I added a fixture with a TOTP-only policy, and the test checks that it comes out false."*

**Mock or fake**
A stand-in for a real system, used in tests or demos so you don't need live access.
*"`collector.py` ships with a fake identity provider that returns four policies, so you can run it without credentials."*

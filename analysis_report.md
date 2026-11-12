# Authentication Event Analysis

Source: `sample_data.csv`.

## 1. Data Scope and Quality

- Number of valid events: **100**.
- Time range: **1–1** (span: 0 s).
- Unique user accounts (`U...@...`): **5**.
- Unique destination computers: **48**.
- User-account events (`U...@...`): **6** (5 accounts, 0 destination computer(s)).
- Successful events: **100**; failures: **0**.
- Invalid records skipped: **0**.

The selected fragment may not represent the full time range. Time-series conclusions should therefore be treated as local to this fragment and validated against a longer baseline.

## 2. Descriptive Statistics

| Feature | Distribution |
|---|---|
| Authentication type | ?: 36, Negotiate: 36, Kerberos: 26, NTLM: 1, MICROSOFT_AUTHENTICATION_PACKAGE_V1_0: 1 |
| Logon type | Network: 62, Service: 32, Batch: 4, ?: 2 |
| Result | Success: 100 |

Repeated destination computers: **12**. Most frequent destinations:

| Computer | Events |
|---|---:|
| `C586` | 12 |
| `C528` | 11 |
| `C625` | 8 |
| `C467` | 8 |
| `C612` | 4 |
| `C1065` | 4 |
| `C457` | 4 |
| `C553` | 4 |
| `C529` | 3 |
| `C988` | 2 |

## 3. Detected Anomalies

Successful user-account logons (`U...@...`, regardless of the column) from one computer to another are treated as potentially suspicious. Service accounts and computer accounts (`C...$`) are excluded because they are common operational noise in LANL data.

- Potential lateral-movement records detected: **0**.
- Affected user accounts: **0**; destination computers: **0**.

| User | Destination computer | Result | Count |
|---|---|---|---:|

### Failed-login indicators

- Failed authentication events: **0**.
- Failed events involving user accounts: **0**.
- User accounts with failures: **0**.

A high concentration of failures for one account or source computer would be consistent with brute force or password spraying. This fragment should be compared with a longer baseline before treating it as a confirmed attack.

| User | Failed attempts |
|---|---:|

## 4. Conclusion

The analysis tests two attack hypotheses: **credential attacks** (brute force/password spraying) and **lateral movement using a compromised user account**.

1. The fragment contains 0 failed authentication event(s).
2. It contains 0 successful user-account logon(s) between different computers.
3. Reuse of one account across multiple hosts is consistent with lateral movement; repeated failures would support a credential-attack hypothesis.

The specific technique and event order cannot be confirmed from authentication data alone. To validate this hypothesis, correlate the results with `proc`, `flows`, `dns`, and `redteam` data.

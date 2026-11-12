# Authentication Event Analysis

Source: `sample_data.csv`.

## 1. Data Scope and Quality

- Number of events: **100**.
- Time range: **1–1** (span: 0 s).
- Unique user accounts (`U...@...`): **5**.
- Unique destination computers: **48**.
- User-account events (`U...@...`): **6** (5 accounts, 1 destination computer(s)).
- Successful events: **100**; failures: **0**.

All records in the sample have timestamp `1`, so time-series analysis and burst detection are inconclusive. The results below describe cross-sectional patterns rather than changes over time.

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

- Potential lateral-movement records detected: **1**.
- Affected user accounts: **1**; destination computers: **1**.

| User | Destination computer | Result | Count |
|---|---|---|---:|
| `U188@DOM1` | `C467` | success | 1 |

## 4. Conclusion

The most likely simulated attack is **lateral movement using a compromised user account**, potentially involving **pass-the-hash or credential reuse**. Evidence:

1. 1 successful user-account logon(s) connect different source and destination computers.
2. This pattern differs from local service and machine logons, which dominate normal activity.
3. Reusing the same account across multiple hosts is consistent with an attacker moving through the network.

The specific technique and event order cannot be confirmed because the sample does not contain all 58 days and every record has the same timestamp. To validate this hypothesis, analyze the full `auth.txt.gz` file and correlate it with `proc`, `flows`, `dns`, and `redteam` data.

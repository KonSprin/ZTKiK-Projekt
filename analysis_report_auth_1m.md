# Authentication Event Analysis

Source: `/Users/tomaszzoltak/Desktop/ZTKIK/DANE 1/auth`.

## 1. Data Scope and Quality

- Number of valid events: **1000000**.
- Time range: **1–10208** (span: 10207 s).
- Unique user accounts (`U...@...`): **1689**.
- Unique destination computers: **4094**.
- User-account events (`U...@...`): **243347** (1689 accounts, 299 destination computer(s)).
- Successful events: **993123**; failures: **6877**.
- Invalid records skipped: **0**.

The selected fragment may not represent the full time range. Time-series conclusions should therefore be treated as local to this fragment and validated against a longer baseline.

## 2. Descriptive Statistics

| Feature | Distribution |
|---|---|
| Authentication type | ?: 583802, Kerberos: 359942, NTLM: 41041, Negotiate: 14442, MICROSOFT_AUTHENTICATION_PACKAGE_V1_0: 644, MICROSOFT_AUTHENTICATION_PACKAG: 62, MICROSOFT_AUTHENTICATION_PACKAGE: 38, MICROSOFT_AUTHENTICATION_PACKAGE_V1: 17, MICROSOFT_AUTHENTICATION_PACKAGE_: 7, MICROSOFT_AUTHENTICATION_PAC: 3, MICROSOFT_AUTHENTICATION_PA: 1, MICROSOFT_AUTHENTICATION_PACK: 1 |
| Logon type | Network: 827731, ?: 152887, Service: 9587, Interactive: 5113, Batch: 3596, NetworkCleartext: 841, NewCredentials: 157, Unlock: 48, RemoteInteractive: 31, CachedInteractive: 9 |
| Result | Success: 993123, Fail: 6877 |

Repeated destination computers: **4049**. Most frequent destinations:

| Computer | Events |
|---|---:|
| `C586` | 133651 |
| `C457` | 99257 |
| `C529` | 76721 |
| `C612` | 74917 |
| `C625` | 71083 |
| `C528` | 67254 |
| `C467` | 67216 |
| `C1065` | 59683 |
| `C2106` | 26986 |
| `C101` | 18391 |

## 3. Detected Anomalies

Successful user-account logons (`U...@...`, regardless of the column) from one computer to another are treated as potentially suspicious. Service accounts and computer accounts (`C...$`) are excluded because they are common operational noise in LANL data.

- Potential lateral-movement records detected: **7057**.
- Affected user accounts: **1404**; destination computers: **299**.

| User | Destination computer | Result | Count |
|---|---|---|---:|
| `U22@DOM1` | `C528` | success | 3605 |
| `U22@DOM1` | `C586` | success | 2703 |
| `U22@DOM1` | `C457` | success | 1206 |
| `U22@DOM1` | `C612` | success | 1150 |
| `U22@DOM1` | `C1065` | success | 1058 |
| `U22@DOM1` | `C625` | success | 1017 |
| `U22@DOM1` | `U22` | success | 784 |
| `U51@DOM1` | `C1487` | success | 680 |
| `U78@DOM1` | `C529` | success | 674 |
| `U292@DOM1` | `C1617` | success | 474 |
| `U292@DOM1` | `C567` | success | 471 |
| `U292@DOM1` | `C1794` | success | 449 |
| `U22@DOM1` | `C2106` | success | 436 |
| `U292@DOM1` | `C1114` | success | 408 |
| `U292@DOM1` | `C104` | success | 395 |

### Failed-login indicators

- Failed authentication events: **6877**.
- Failed events involving user accounts: **3837**.
- User accounts with failures: **111**.

A high concentration of failures for one account or source computer would be consistent with brute force or password spraying. This fragment should be compared with a longer baseline before treating it as a confirmed attack.

| User | Failed attempts |
|---|---:|
| `U22@DOM1` | 1705 |
| `U207@?` | 267 |
| `U199@?` | 245 |
| `U1825@?` | 243 |
| `U10770@DOM1` | 190 |
| `U199@DOM1` | 136 |
| `U1829@?` | 125 |
| `U73@?` | 119 |
| `U252@DOM1` | 85 |
| `U73@DOM1` | 74 |
| `U1702@?` | 59 |
| `U1829@DOM1` | 34 |
| `U53@DOM1` | 34 |
| `U761@?` | 31 |
| `U589@DOM1` | 27 |

## 4. Conclusion

The analysis tests two attack hypotheses: **credential attacks** (brute force/password spraying) and **lateral movement using a compromised user account**.

1. The fragment contains 6877 failed authentication event(s).
2. It contains 67718 successful user-account logon(s) between different computers.
3. Reuse of one account across multiple hosts is consistent with lateral movement; repeated failures would support a credential-attack hypothesis.

The specific technique and event order cannot be confirmed from authentication data alone. To validate this hypothesis, correlate the results with `proc`, `flows`, `dns`, and `redteam` data.

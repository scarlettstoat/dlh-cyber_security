# Financial Trading Platform Threat Model

## 1. Most Critical CIA Component

The most critical CIA component for this system is **Integrity**.

A trading platform needs to make sure that stock prices, balances, buy/sell orders, fund transfers, and automated trading rules cannot be changed without authorisation.

For example, if an attacker changes an order from buying **10 shares to 1,000 shares**, the platform could cause a major financial loss even if it remains fully available.

Availability is also extremely important because the system requires **99.99% uptime**. Users need to be able to react quickly to market changes, cancel orders, and access their accounts.

A reasonable priority would therefore be:

1. **Integrity**
2. **Availability**
3. **Confidentiality**

Confidentiality still matters because account information, balances, trading strategies, and personal data must remain private.

### Can security conflict with performance?

Yes. The platform also requires trades to complete in less than **100 ms**, while security controls such as authentication, encryption, logging, and fraud detection require extra processing.

For example, performing several complex security checks before every trade could increase latency.

The solution is not to remove security controls, but to design them efficiently. This could include:

- Fast server-side authorisation checks
- Efficient encryption
- Asynchronous logging where appropriate
- Real-time fraud checks focused on high-risk actions
- Caching information that does not affect transaction integrity

Security and performance therefore have to be balanced without weakening important controls.

---

# 2. Threat Model: Automated Trading Rules

Automated trading rules are high risk because they can execute transactions without the user manually approving every trade.

## Risk 1 — Unauthorised Rule Modification

| Item | Analysis |
|---|---|
| **Threat** | An attacker changes a user's automated trading rule. |
| **Attack scenario** | An attacker compromises an account and changes a rule from "sell 10 shares if the price drops below €100" to "sell all shares immediately". |
| **Impact** | Financial loss, unwanted trades, regulatory complaints, and loss of customer trust. |
| **Likelihood** | **High** if account security and authorisation are weak. |
| **Mitigation** | Require MFA for sensitive changes, re-authenticate users before changing trading rules, perform server-side authorisation, send notifications for rule changes, and keep audit logs. |

---

## Risk 2 — Logic Flaws in Trading Rules

| Item | Analysis |
|---|---|
| **Threat** | A bug or badly designed rule causes unintended trades. |
| **Attack scenario** | A user creates a rule that should buy once when a stock reaches a certain price, but a logic error causes the system to execute the order repeatedly. |
| **Impact** | Large financial losses, excessive trading, incorrect balances, and possible regulatory issues. |
| **Likelihood** | **Medium.** Automated systems can behave unexpectedly if rules are not validated properly. |
| **Mitigation** | Validate rules before activation, set transaction limits, test rule logic, prevent duplicate execution, and allow users to pause or disable automated trading quickly. |

---

## Risk 3 — Race Conditions / Duplicate Trades

| Item | Analysis |
|---|---|
| **Threat** | Multiple processes act on the same trading condition at nearly the same time. |
| **Attack scenario** | A stock reaches the trigger price and two backend processes detect the event simultaneously. Both execute the same automated order before the system records that the first trade has already completed. |
| **Impact** | Duplicate trades, unexpected losses, incorrect account balances, and transaction disputes. |
| **Likelihood** | **Medium**, especially in a high-speed system handling many requests at once. |
| **Mitigation** | Use transaction locking, unique transaction IDs, idempotency controls, atomic database operations, and checks to make sure a trading rule cannot execute twice for the same event. |

---

# 3. Defence in Depth After Account Compromise

If an attacker compromises a user's account, the platform should still have several additional controls to limit the damage.

## Layer 1 — MFA and Re-authentication

Require MFA and re-authentication before sensitive actions such as:

- Changing automated trading rules
- Transferring large amounts of money
- Adding a new bank account
- Changing security settings

This prevents a stolen session from automatically giving the attacker full control.

## Layer 2 — Transaction Limits

Set limits for:

- Maximum trade value
- Daily transfers
- Large withdrawals
- Automated trading activity

Very large or unusual actions could require additional verification.

## Layer 3 — Anomaly and Fraud Detection

Monitor behaviour such as:

- Login from a new country or device
- Sudden large trades
- Rapid changes to automated rules
- Multiple fund transfers
- Activity that does not match the user's normal behaviour

Suspicious activity could trigger extra authentication or temporarily block the transaction.

## Layer 4 — Secure Session Management

Use:

- Short-lived session tokens
- Secure cookies or tokens
- Automatic logout after inactivity
- Session revocation
- Detection of unusual simultaneous sessions

If a session is suspected of being stolen, it should be possible to terminate it quickly.

## Layer 5 — Authorisation and Least Privilege

Every sensitive action should be checked on the server.

A compromised user account should only have access to that user's authorised accounts and actions. Administrative functions must remain separate.

## Layer 6 — Audit Logs and Alerts

Record important events such as:

- Logins
- Trades
- Fund transfers
- Rule creation or modification
- Security-setting changes
- Failed authentication attempts

Users should also receive alerts for important account changes and unusual transactions.

This helps detect attacks quickly and provides evidence during an investigation.

---

# 4. Summary

For this trading platform, **Integrity is the most important CIA component** because incorrect or manipulated trades can cause immediate financial damage. Availability is a close second because the platform must remain accessible during fast-moving markets.

The main risks to automated trading rules are:

1. **Unauthorised rule changes**
2. **Logic flaws**
3. **Race conditions and duplicate trades**

These risks can be reduced through strong authentication, server-side authorisation, transaction limits, validation, idempotency controls, monitoring, and audit logging.

If an account is compromised, defence in depth should make sure that one stolen password or session does not automatically give an attacker unlimited control of the user's money and trades.

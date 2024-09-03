## ENS DNSSEC Debugger

#### What do the DNSSEC debug results mean?

| Indicator                | **Yes** means                                                                      | **No** means                                                                 |
|--------------------------|------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **DNSSEC Enabled**        | The domain has DNSSEC configured and enabled.                                       | The domain is not using DNSSEC, potentially vulnerable to DNS spoofing attacks. |
| **DNSSEC Validated**      | The DNSSEC chain of trust was successfully validated.                               | Issues in the DNSSEC chain, possibly due to misconfiguration or expired signatures. |
| **Valid DNSKEY**          | The domain has valid DNSKEY records used to sign other DNS records.                 | DNSKEY records are missing, expired, or invalid, breaking the DNSSEC chain.      |
| **Valid DS**              | Valid Delegation Signer (DS) records exist in the parent zone.                      | DS records are missing or invalid, breaking the chain of trust from the parent zone. |
| **Matching DS and DNSKEY**| The DS record correctly matches one of the DNSKEY records.                          | Mismatch between DS and DNSKEY records, breaking the DNSSEC chain.                |
| **All RRSIGs Valid**      | All Resource Record Signatures are valid and not expired.                           | One or more RRSIG records are invalid or expired, causing potential validation failures. |
| **ENS record set**        | The domain has an ENS1 TXT record for ENS Gasless DNSSEC integration.               | No ENS1 record present. Not an error, but the domain isn't set up for ENS resolution. |

#### Are my TLDs DNSSEC-Supported?

For an up-to-date list of DNSSEC-supported Top-Level Domains (TLDs), you can refer to the following resources:

- [ICANN TLD DNSSEC Report](https://stats.research.icann.org/dns/tld_report/)
- [Internet Society DNSSEC Maps](https://www.internetsociety.org/deploy360/dnssec/maps/)

Note that DNSSEC support can change over time, so it's always best to check the most recent information or consult with your domain registrar.

---
title: "CyberArk Certificate Manager (Venafi)"
toc_hide: true
---

Import a [CyberArk Certificate Manager](https://www.cyberark.com/products/certificate-manager/)
(formerly Venafi) certificate inventory export.

This exists for organisations that cannot grant API credentials — air-gapped networks, procurement
restrictions, a pending security review. The DefectDojo Pro connector pulls the same data over the API;
this parser accepts the same data as a file.

### Certificate posture is computed, not reported

**Neither edition returns a compliance verdict.** The export is an inventory of certificates, and the
posture rules are computed from each certificate's own attributes:

| Rule | Severity | Condition |
| --- | --- | --- |
| `expired` | Critical | the expiry is in the past |
| `expiring-soon` | High | the expiry is within **30 days** |
| `weak-key` | High | an **RSA** key shorter than **2048** bits |
| `weak-signature` | High | the signature hash is SHA1, MD5 or MD2 |
| `self-signed` | Medium | the certificate is self-signed |

So **one certificate produces zero findings when it is healthy** and several when it breaks several
rules. A rule is **skipped when the attribute it needs is absent** rather than guessed: a certificate
with no recorded key size is not reported as weak, and one with no recorded expiry is not reported
either way — guessing would either raise a false alarm or hide a real lapse.

Only **RSA** keys are measured against the 2048-bit floor. An elliptic-curve key is much shorter by
design, so applying the same floor would report every EC certificate as weak.

Hyphens are stripped before the hash check, so `SHA-1` and `SHA1` are both recognised.

**Expiry is judged against the time of import**, exactly as the connector judges it against sync time.
The same file imported later therefore reports more expiries — which is correct, not a defect: a
certificate that has since lapsed really has lapsed.

### File Types

JSON. Both editions are read, and they name their fields differently:

- **SaaS**: `{"certificates": [...]}` — `fingerprint`, `subjectCN` (a **list**), `subjectDN`,
  `subjectAlternativeNamesByType` (a map keyed by SAN type), `issuerCN`, `keyStrength`,
  `encryptionType`, `signatureHashAlgorithm`, `validityEnd`, `selfSigned`.
- **Self-hosted**: `{"Certificates": [...]}` — capitalised throughout: `Thumbprint`, `Guid`, `DN`, `CN`,
  `Subject`, `Issuer`, `KeySize`, `KeyAlgorithm`, `SignatureAlgorithm`, `ValidTo`.

A bare array works too. Reading only one edition's names would silently produce **no findings at all**
against the other, because every rule's attribute would look absent.

The self-hosted edition has **no self-signed flag**, so it is inferred from the subject matching the
issuer — which is what self-signed means.

### Fields worth noting

- **Title** is the posture problem with the certificate's common name in brackets.
- **Identity** is `venafi-<fingerprint>-<rule>`, preferring the fingerprint (or thumbprint) over the
  record id, because that is the value that identifies the certificate itself.
- **The certificate is the component**, named by common name and falling back to the fingerprint, so
  the same problem on two certificates stays two findings.
- **Subject alternative names are sorted here**, unlike the connector — it iterates a Go map, whose
  order is randomised, so its own rendering of that line varies between syncs. Sorting keeps a file
  import stable; the line is not part of the deduplication hash, so the two still match.
- **Timestamps** are accepted as RFC 3339, with milliseconds, without a timezone, or as a bare date.
  One with no timezone is read as UTC.

### Sample Scan Data

Sample scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/venafi).

The samples cover a SaaS certificate breaking four rules at once, an elliptic-curve certificate that must
*not* be flagged as weak, a healthy certificate producing nothing, one with no attributes at all, one
whose weak hash is named only in the fallback field, and a self-hosted export whose self-signed status has
to be inferred. Common names, issuers and fingerprints are generic, and no fixture contains a real
certificate or key.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name

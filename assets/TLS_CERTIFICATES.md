# IUH HTTPS chain

The IUH server was observed on 2026-10-31 sending only its leaf certificate,
omitting RapidSSL TLS RSA CA G1. Python Requests consequently failed with
`CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`.

`rapidssl-tls-rsa-ca-g1.pem` is the public intermediate certificate downloaded
with HTTPS verification from the CA's official distribution endpoint:
https://cacerts.digicert.com/RapidSSLTLSRSACAG1.crt (DER converted to PEM).

SHA-256 certificate fingerprint:
`4422e963ee53cd58cc9f85cd40bf5ffec0095fdf1a154535661c1c06bcadc69b`

Issuer: DigiCert Global Root G2. Intermediate expires 2027-11-02.
It was verified against the system root store before inclusion.

The bot loads the Requests root bundle plus this intermediate into an isolated
TLS context mounted only for `https://doantn.iuh.edu.vn/`. It does not trust the
IUH leaf certificate directly. Partial-chain trust is disabled; root signature,
hostname and expiry checks remain active. Telegram uses its default adapter.
Explicit custom CA bundles (e.g. REQUESTS_CA_BUNDLE) retain Requests semantics.
No certificate is fetched at runtime. If IUH changes its issuer, refresh this
file from the official CA source and verify the chain again.

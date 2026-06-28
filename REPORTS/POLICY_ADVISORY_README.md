# Policy Advisory — Preinstalled Privileged APKs in Consumer Firmware

Purpose
- Provide regulators, national CSIRTs, and technical policy teams with a concise advisory and operational checklist for triaging, coordinating, and remediating preinstalled privileged APKs discovered in consumer Android firmware (case: Motorola G04s / Unisoc T606).
- Offer short-term containment steps, medium-term vendor coordination guidance, and long-term policy recommendations.

Audience
- Technical/regulatory teams at IFT, PROFECO, CERT-MX, and related Mexican agencies; also useful for vendor security teams and CERT/CSIRT partners.

Executive summary
- Independent research has identified multiple preinstalled, privileged Android packages in certain consumer firmware images that may collect telemetry, access telephony/location/camera capabilities, or perform installer/update actions without clear user consent. These behaviors pose privacy and consumer-protection risks and warrant immediate regulatory attention and coordinated remediation.

Immediate actions (0–7 days)
1. Acknowledge and accept artifacts
   - Ask vendors (OEMs and component vendors) to acknowledge receipt of this advisory within 7 days.
   - Provide a secure intake path (PGP/SFTP) for sample artifacts, YARA rules and hashes. Do not accept full APKs via public channels.
2. CSIRT triage
   - CERT-MX (or equivalent) should accept artifacts and perform an initial technical triage to validate IOCs and scope.
   - Use the repository’s YARA rules and SHA256 hashes for initial scanning.
3. Containment advisory (interim)
   - If an immediate privacy or consumer risk is confirmed, issue a short guidance to consumers with safe steps to check/disable suspicious packages (see Consumer Advisory template below).
   - Optionally advise ISPs and enterprise networks to monitor/block the listed IOC domains while investigating.
4. Document and preserve evidence
   - Record timestamps, firmware versions, device models, and all steps taken; preserve checksums and signed logs for legal and forensic chains.

Short-term technical tasks (7–30 days)
1. Vendor remediation plan
   - Require vendors to submit a remediation plan and firmware BOM for affected builds.
   - Ask for confirmation whether the component is intentionally preinstalled and its purpose.
2. Independent verification
   - Commission or coordinate independent technical review (CERT-MX or accredited third party) to confirm telemetry flows and data types collected.
3. Disclosure coordination
   - Agree coordinated disclosure timelines with vendor; consider CVE/MITRE/CERT-CC involvement if appropriate.
4. Consumer protection steps
   - If vendors cannot remediate quickly, regulators should provide consumer guidance and consider temporary mitigations.

Long-term policy recommendations
1. Firmware transparency & BOM
   - Require OEMs/distributors to publish a firmware bill-of-materials (preinstalled apps, signing certs, permission lists) for each firmware build distributed in Mexico.
2. Preinstall security certification
   - Establish a security audit/certification requirement for privileged preinstalled components.
3. Supply-chain scanning mandate
   - Mandate static/signature scanning (YARA, signing checks) as part of firmware acceptance for devices sold in Mexico.
4. Consumer controls and notices
   - Require practical, supported means for end users to disable or uninstall non-essential preinstalled apps and clear privacy notices at first boot/activation.
5. Incident reporting SLAs
   - Define mandatory vendor SLAs for acknowledgement and remediation of firmware-level privacy/security issues.
6. Enforcement
   - Consider penalties and regulatory consequences for undisclosed telemetry or unjustified privileged components shipped to consumers.

Secure artifact handling & intake checklist
- Accept artifacts only via PGP-encrypted archive or SFTP managed by the CSIRT.
- Require submitter to provide:
  - SHA256 of each artifact
  - Minimal, redacted context (device model, firmware version)
  - YARA rules and reproduction steps
- Validate integrity on receipt (verify checksums and PGP signature).
- Limit distribution of full binaries; provide redacted manifests and non-sensitive logs for public advisories.
- Use a documented chain-of-custody for all artifact transfers.

Technical triage checklist (for CSIRT)
- Confirm SHA256 matches reported IOCs.
- Run provided YARA rules against firmware/APK.
- Inspect manifest for privileged permissions, exported components, and secret-code receivers.
- Capture network traffic (pcap) in an isolated lab if dynamic behavior is suspected.
- Identify certificate signing metadata and compute cert fingerprints for detection.
- Produce a concise technical memo for regulators and vendor contacts.

Suggested consumer advisory template (short)
- Title: Security advisory — Check preinstalled apps on Moto G04s
- Body (short): Research indicates some Moto G04s firmware may include preinstalled apps with privileged permissions that could collect telemetry or act as installers. We recommend:
  1) Back up important data.
  2) If you can, check for the presence of these packages or seek vendor guidance (contact info below).
  3) Avoid installing unknown apps until vendor guidance is provided.
- Note: Provide safe, non-technical instructions or refer consumers to vendor support channels. Avoid instructions that require rooting.

Legal & regulatory considerations
- Data protection: Evaluate obligations under the Ley Federal de Protección de Datos Personales (LFPDPPP) for potential unauthorized processing/exfiltration of personal data.
- Consumer protection: Assess whether undisclosed telemetry or privileged preinstalled apps violate consumer rights and labeling/notice obligations.
- Criminal/privacy risk: Avoid encouraging any activity that may involve unauthorized access to other people’s devices; ensure investigations use legally obtained devices/samples.
- Seek legal counsel before public release of sensitive artifacts.

Suggested disclosure & timeline (recommended)
- Day 0–7: Receive and validate artifacts; request vendor acknowledgement.
- Day 7–30: Independent technical analysis and vendor remediation plan; interim consumer guidance if risk is confirmed.
- Day 30–90: Remediation implementation and coordinated advisory/public notice.
- >90 days: Consider regulatory enforcement actions or broader policy changes if systemic problems are found.

Contact & secure intake
- Researcher contact: lexs201992 — lexs201992@gmail.com
- Repo with technical artifacts and YARA rules: https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum
- Proposed intake methods: PGP-encrypted archive to CERT-MX managed address, or SFTP link provided by CERT-MX.

Recommended next steps for regulators
1. Accept this advisory and set up a secure intake with the researcher or CERT-MX.
2. Triage with CERT-MX using the provided YARA rules and hashes.
3. Contact the relevant vendors (Motorola, Unisoc, InMobi, Longcheer) for immediate acknowledgement and remediation plans.
4. Consider a short consumer advisory if evidence confirms a user-impacting privacy risk.

Appendix
- Include links to YARA rules and the consolidated technical report in the repo.
- Provide contact for researcher and any supporting technical reviewers.

---

If you’d like me to make additional edits (Spanish translation, shorter one-page summary, or to add a PROFECO-style consumer advisory), tell me and I will update the file.
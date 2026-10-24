# Phishing Shield — Enterprise Upgrade Implementation Plan

## 1. Codebase Inspection Summary
- **Runtime & Framework**: React 19 SPA on Vite + Node.js Express backend (`server.ts`) running concurrently on port 3000.
- **Database & Auth**: Firebase Auth + Cloud Firestore (`ai-studio-eaa97cdf-4bc0-418b-a9ab-36008b64778a`), with strict ABAC rules (`firestore.rules`) and schema (`firebase-blueprint.json`).
- **Existing Scanners**:
  - `urlAnalyzer.ts`: Lexical, TLS X.509 certificate check, punycode/homograph detection, DNS resolution, RDAP domain age, Abuse.ch URLhaus threat intel.
  - `messageAnalyzer.ts`: Multi-category NLP heuristics, regex intent classification, SPF/DKIM/DMARC headers, embedded URL inspection.
  - `screenshotAnalyzer.ts`: Multipart image upload (PNG/JPG/WEBP <= 10MB), Sharp image processing, jsQR matrix detection, Tesseract.js / Gemini Multimodal Vision OCR, EXIF metadata extraction.
  - `ipAnalyzer.ts`: IPv4/IPv6 classification, Reverse DNS PTR, ASN lookup, live DNSBL zone queries (Spamhaus, Barracuda, SpamCop).
  - `geminiService.ts`: Gemini 3.8 Flash, Live Voice (`gemini-3.8-live`), Google Search Grounding (`gemini-3.8-flash` with `googleSearch`), Flash TTS, audio transcription (`gemini-3.5-transcribe`).
  - 3D Matrix (`CyberMatrix3D.tsx`): Procedural Three.js 12-part shield core with PBR environment and radar sweep.
- **Gaps Identified vs User Brief**:
  1. **Dashboard Navigation**: Need all 15 requested dashboard workspaces:
     - Dashboard Overview
     - Scan URL
     - Scan Message
     - Scan Screenshot
     - Scan QR Code (dedicated workspace & `POST /api/scan-qr`)
     - Scan Public IP
     - Domain Intelligence (dedicated workspace & `POST /api/scan-domain`)
     - Scan History
     - Security Reports
     - Security Awareness (interactive quizzes & exercises)
     - Security Analytics (real statistics derived from actual records)
     - AI Security Assistant (Gemini & optional Claude chat)
     - Profile (Analyst credentials & organization)
     - Security Settings & System Status (`GET /api/system-status`)
     - Logout
  2. **Dedicated Endpoints**:
     - `POST /api/scan-qr`: Dedicated image/camera QR code scanner with safe URL decoding and threat analysis.
     - `POST /api/scan-domain`: Pure domain intelligence (DNS records, RDAP age, registrar, nameservers, reputation).
     - `POST /api/ai/explain`: Reusable endpoint for verified Gemini AI threat explanations in Hindi, English, and Hinglish.
     - `POST /api/ai/claude/chat`: Claude AI cybersecurity chat endpoint (checks for `ANTHROPIC_API_KEY`; reports `NOT CONFIGURED` safely if absent).
     - `GET /api/history` and `GET /api/history/:scanId`: REST endpoints mirroring client Firestore access.
     - `POST /api/feedback`: Continuous improvement feedback endpoint.
  3. **UI / Styling Compliance**:
     - Professional cybersecurity SaaS aesthetic: Clean white background, dark charcoal text, blue/indigo and emerald accents, light gray borders, subtle shadows, mobile-first responsive layout.
     - Header branding: "PHISHING SHIELD" / "Detect. Analyze. Protect."
     - Landing headline: "Your Digital Shield Against Phishing & Online Scams" with Get Started, Scan Now, How It Works, Security Features, and Privacy Information.

---

## 2. Implementation Stages

### Stage 1: Backend APIs & Analyzer Extensions
1. Implement `POST /api/scan-qr` using Sharp + jsQR, integrating with `analyzeUrlTarget`.
2. Implement `POST /api/scan-domain` for deep DNS records (A, AAAA, MX, TXT, NS, CAA, SOA) and RDAP registry data.
3. Implement `POST /api/ai/explain` and `POST /api/ai/claude/chat` with graceful error handling and key verification.
4. Enhance `GET /api/system-status` to report real operational states for all 12 platform subsystems.
5. Add `POST /api/feedback` for reporting false positives/negatives.

### Stage 2: UI Dashboard Workspaces
1. **Dashboard Overview**: Central command center with real scan telemetry KPI cards, quick scan action bar, live threat radar preview, and recent activity ledger.
2. **Dedicated QR Scanner (`ScanQrWorkspace`)**: File drag-and-drop or webcam capture for QR codes, with safe payload decoding and URL threat integration.
3. **Dedicated Domain Intelligence (`DomainIntelWorkspace`)**: Deep domain inspection interface displaying DNS records table, RDAP registration history, and certificate chain.
4. **Dedicated Screenshot Scanner UI**: Expose the screenshot and image analyzer as a first-class dashboard section with image preview and OCR highlights.
5. **Security Awareness & Training (`SecurityAwarenessWorkspace`)**: Interactive scenario-based quizzes (Phishing URLs, Urgent Wire Requests, QR Code Fraud, OTP Safety) with instant educational feedback.
6. **Security Analytics (`SecurityAnalyticsWorkspace`)**: Visual charts and distribution breakdown based on actual scan history.
7. **System Status & Settings (`SystemStatusWorkspace`)**: Live health checks for all security engines and privacy retention controls.

### Stage 3: Verification, Testing & Polish
1. Run TypeScript linter (`lint_applet`) and verify zero errors.
2. Compile and test applet (`compile_applet`).
3. Verify live endpoints using `curl`.

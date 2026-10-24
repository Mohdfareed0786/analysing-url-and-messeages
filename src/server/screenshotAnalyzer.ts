import sharp, { type Metadata as SharpMetadata } from 'sharp';
import jsQR from 'jsqr';
import exifr from 'exifr';
import { Type } from '@google/genai';
import { analyzeUrlTarget } from './urlAnalyzer.ts';
import type { EvidenceIndicator, ExternalFeedStatus } from './ipAnalyzer.ts';
import { getGenAIClient, formatGeminiErrorMessage, type AIExplanationResult } from './geminiService.ts';

export type ScreenshotRiskClassification =
  | 'LOW RISK'
  | 'MEDIUM RISK'
  | 'HIGH RISK'
  | 'CRITICAL RISK';

export interface ExtractedUrlScanSummary {
  url: string;
  source: 'OCR Text' | 'QR Code' | 'Visual Address Bar';
  registeredDomain: string;
  tld: string;
  usesHttps: boolean;
  domainAge: string;
  creationDate: string;
  registrar: string;
  resolvedIp: string;
  ipOrganization: string;
  ipCountry: string;
  dnsResolvable: boolean;
  spfRecord: string;
  dmarcRecord: string;
  isShortener: boolean;
  isIpHostname: boolean;
  isPunycode: boolean;
  suspiciousKeywords: string[];
  homographIndicators: string[];
  brandMismatchWithVisual: string | null;
  riskScore: number;
  verdict: string;
  threatIntelligence: ExternalFeedStatus[];
  evidence: EvidenceIndicator[];
}

export interface QrCodeAnalysisResult {
  checked: boolean;
  detected: boolean;
  decodedContent: string | null;
  payloadType: 'URL' | 'Payment / UPI URI' | 'Deep Link' | 'Plain Text' | 'None';
  urlAnalysis: ExtractedUrlScanSummary | null;
  riskSummary: string;
}

export interface VisualSecurityInspection {
  available: boolean;
  engine: string;
  screenshotCategory: string;
  containsLoginForm: boolean;
  containsPasswordInput: boolean;
  containsOtpInput: boolean;
  containsPaymentCardInput: boolean;
  containsUrgencyBanner: boolean;
  containsFakeAddressBar: boolean;
  containsDownloadPrompt: boolean;
  visualIndicators: string[];
  uiAuthenticityAssessment: string;
}

export interface BrandImpersonationAnalysis {
  detectedBrand: string | null;
  officialDomains: string[];
  impersonationRisk: 'None Detected' | 'Possible Brand Reference' | 'High-Confidence Impersonation';
  brandDomainMismatch: boolean;
  mismatchDetails: string;
}

export interface SocialEngineeringScreenshotAnalysis {
  urgencyIndicators: string[];
  fearOrThreatLanguage: string[];
  authorityImpersonation: string[];
  rewardOrLotteryScam: string[];
  credentialHarvestingRequests: string[];
  financialOrPaymentRequests: string[];
  detectedScamPatterns: string[];
  manipulationScore: number;
}

export interface ImageMetadataReport {
  fileName: string;
  mimeType: string;
  format: string;
  fileSizeBytes: number;
  formattedFileSize: string;
  width: number;
  height: number;
  dimensions: string;
  colorSpace: string;
  channels: number;
  hasAlpha: boolean;
  exifAvailable: boolean;
  exifSoftware: string;
  exifDeviceMakeModel: string;
  exifDateTime: string;
}

export interface ScreenshotAnalysisResult {
  scanType: 'screenshot';
  targetName: string;
  riskScore: number;
  verdict: ScreenshotRiskClassification;
  confidenceScore: number;
  metadata: ImageMetadataReport;
  ocr: {
    status: 'Extracted' | 'Partial / Low Clarity' | 'No Text Found' | 'Unavailable';
    engine: string;
    extractedText: string;
    lowClarityNotice: string | null;
    characterCount: number;
    lineCount: number;
    extractedUrls: string[];
    extractedDomains: string[];
    extractedEmails: string[];
    extractedPhones: string[];
  };
  qrCode: QrCodeAnalysisResult;
  visualInspection: VisualSecurityInspection;
  brandImpersonation: BrandImpersonationAnalysis;
  socialEngineering: SocialEngineeringScreenshotAnalysis;
  urlAnalyses: ExtractedUrlScanSummary[];
  threatIntelligence: ExternalFeedStatus[];
  evidence: EvidenceIndicator[];
  aiExplanation: AIExplanationResult;
  scannedAt: string;
}

const KNOWN_BRAND_DOMAINS: Record<string, string[]> = {
  paypal: ['paypal.com', 'paypal.me'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com'],
  google: ['google.com', 'accounts.google.com', 'gmail.com', 'youtube.com', 'withgoogle.com'],
  apple: ['apple.com', 'icloud.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com'],
  netflix: ['netflix.com'],
  chase: ['chase.com', 'jpmorganchase.com'],
  wellsfargo: ['wellsfargo.com'],
  bankofamerica: ['bankofamerica.com', 'bofa.com'],
  citibank: ['citi.com', 'citibank.com', 'citigroup.com'],
  sbi: ['onlinesbi.sbi', 'sbi.co.in'],
  hdfc: ['hdfcbank.com'],
  icici: ['icicibank.com'],
  axis: ['axisbank.com'],
  coinbase: ['coinbase.com'],
  binance: ['binance.com', 'binance.us'],
  metamask: ['metamask.io'],
  dhl: ['dhl.com'],
  fedex: ['fedex.com'],
  usps: ['usps.com'],
  indiapost: ['indiapost.gov.in'],
  irs: ['irs.gov'],
  linkedin: ['linkedin.com'],
  facebook: ['facebook.com', 'fb.com', 'meta.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com'],
  telegram: ['telegram.org', 't.me'],
  docusign: ['docusign.com', 'docusign.net'],
  dropbox: ['dropbox.com'],
  adobe: ['adobe.com'],
  github: ['github.com'],
  stripe: ['stripe.com'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  discord: ['discord.com', 'discordapp.com'],
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  return `${mb.toFixed(2)} MB`;
}

/**
 * Extract URLs, domains, emails, and phone numbers deterministically from text
 */
function extractEntitiesFromText(rawText: string) {
  const urlSet = new Set<string>();
  const domainSet = new Set<string>();
  const emailSet = new Set<string>();
  const phoneSet = new Set<string>();

  if (!rawText || !rawText.trim()) {
    return {
      urls: [],
      domains: [],
      emails: [],
      phones: [],
    };
  }

  // 1. Emails
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,15}\b/g;
  for (const match of rawText.matchAll(emailRegex)) {
    emailSet.add(match[0].toLowerCase());
  }

  // 2. Explicit HTTP/HTTPS URLs
  const explicitUrlRegex = /https?:\/\/[^\s"'<>)\]]+/gi;
  for (const match of rawText.matchAll(explicitUrlRegex)) {
    const cleaned = match[0].replace(/[.,;:!?)'"\]]+$/, '');
    if (cleaned.length > 8) {
      urlSet.add(cleaned);
    }
  }

  // 3. Bare URLs / Domains with paths or well-known TLDs (excluding email addresses)
  const bareUrlRegex =
    /(?<![A-Za-z0-9@._-])(?:www\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?:\.[a-zA-Z]{2,12})(?:\/[^\s"'<>)\]]*)?/gi;
  const commonFileExtensions = new Set([
    'png',
    'jpg',
    'jpeg',
    'webp',
    'gif',
    'svg',
    'pdf',
    'exe',
    'zip',
    'txt',
    'doc',
    'docx',
    'xls',
    'xlsx',
    'css',
    'js',
  ]);

  for (const match of rawText.matchAll(bareUrlRegex)) {
    const rawCandidate = match[0].replace(/[.,;:!?)'"\]]+$/, '');
    if (rawCandidate.includes('@')) continue;

    const hostPart = rawCandidate.split('/')[0].toLowerCase();
    const parts = hostPart.split('.');
    const tld = parts[parts.length - 1] || '';

    // Skip version numbers or image file names
    if (/^\d+$/.test(tld) || commonFileExtensions.has(tld) || tld.length < 2) {
      continue;
    }

    domainSet.add(hostPart.replace(/^www\./, ''));
    // Check if already covered by explicit URL
    const alreadyCovered = Array.from(urlSet).some((u) =>
      u.toLowerCase().includes(rawCandidate.toLowerCase())
    );
    if (!alreadyCovered) {
      urlSet.add(`https://${rawCandidate}`);
    }
  }

  // Extract domains from explicit URLs too
  for (const u of urlSet) {
    try {
      const parsed = new URL(u);
      domainSet.add(parsed.hostname.toLowerCase().replace(/^www\./, ''));
    } catch {
      // Ignore malformed
    }
  }

  // 4. Phone Numbers (international & local formats, avoiding dates/IDs)
  const phoneRegex = /(?:\+?\d{1,3}[\s.-]?)?\(?\d{3,4}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g;
  for (const match of rawText.matchAll(phoneRegex)) {
    const digits = match[0].replace(/\D/g, '');
    if (digits.length >= 10 && digits.length <= 15) {
      phoneSet.add(match[0].trim());
    }
  }

  return {
    urls: Array.from(urlSet).slice(0, 8),
    domains: Array.from(domainSet).slice(0, 10),
    emails: Array.from(emailSet).slice(0, 8),
    phones: Array.from(phoneSet).slice(0, 8),
  };
}

/**
 * Decode QR codes from image buffer using sharp + jsQR with multi-pass resolution scaling
 */
async function detectAndDecodeQrCode(buffer: Buffer): Promise<{
  detected: boolean;
  decodedContent: string | null;
}> {
  const attempts: { width?: number; greyscale?: boolean }[] = [
    {}, // Original size (capped at 1600px)
    { width: 1000, greyscale: true },
    { width: 600, greyscale: false },
  ];

  for (const attempt of attempts) {
    try {
      let pipeline = sharp(buffer).rotate();
      if (attempt.width) {
        pipeline = pipeline.resize({
          width: attempt.width,
          withoutEnlargement: true,
          fit: 'inside',
        });
      } else {
        pipeline = pipeline.resize({
          width: 1600,
          height: 1600,
          withoutEnlargement: true,
          fit: 'inside',
        });
      }
      if (attempt.greyscale) {
        pipeline = pipeline.normalize();
      }

      const { data, info } = await pipeline
        .ensureAlpha()
        .raw()
        .toBuffer({ resolveWithObject: true });

      const clamped = new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength);
      const qr = jsQR(clamped, info.width, info.height, {
        inversionAttempts: 'attemptBoth',
      });

      if (qr && qr.data && qr.data.trim()) {
        return {
          detected: true,
          decodedContent: qr.data.trim(),
        };
      }
    } catch {
      // Continue to next attempt
    }
  }

  return {
    detected: false,
    decodedContent: null,
  };
}

/**
 * Deterministic social engineering & scam pattern analyzer on extracted screenshot text
 */
function analyzeScreenshotSocialEngineering(
  text: string,
  visualIndicators: string[] = []
): SocialEngineeringScreenshotAnalysis {
  const lower = `${text}\n${visualIndicators.join(' ')}`.toLowerCase();

  const urgencyRules = [
    'immediately',
    'urgent',
    'within 24 hours',
    'within 12 hours',
    'expires today',
    'final notice',
    'action required',
    'act now',
    'immediate attention',
    'last warning',
    'respond immediately',
    'time sensitive',
  ];
  const fearRules = [
    'account suspended',
    'account blocked',
    'temporarily locked',
    'unauthorized login',
    'unusual activity',
    'security alert',
    'compromised',
    'permanently closed',
    'legal action',
    'arrest warrant',
    'kyc expired',
    'sim blocked',
    'pan card blocked',
    'service terminated',
  ];
  const authorityRules = [
    'customer support',
    'helpdesk',
    'security team',
    'fraud department',
    'income tax',
    'irs',
    'customs department',
    'postal service',
    'reserve bank',
    'government',
    'official notification',
    'compliance department',
  ];
  const rewardRules = [
    'congratulations',
    'you have won',
    'lucky winner',
    'claim your reward',
    'cashback reward',
    'free gift',
    'lottery',
    'exclusive giveaway',
    'airdrop claim',
    'bonus credited',
  ];
  const credentialRules = [
    'enter your password',
    'verify your account',
    'confirm your identity',
    'one-time password',
    'share otp',
    'enter otp',
    'verification code',
    'security code',
    'sign in to continue',
    'update credentials',
    'seed phrase',
    'recovery phrase',
    'private key',
    'cvv',
    'atm pin',
  ];
  const financialRules = [
    'payment failed',
    'invoice overdue',
    'wire transfer',
    'upi pin',
    'approve payment',
    'collect request',
    'customs fee',
    'delivery fee',
    'processing fee',
    'gift card',
    'bitcoin',
    'usdt',
    'bank details',
    'update billing',
  ];

  const urgencyIndicators = urgencyRules.filter((w) => lower.includes(w));
  const fearOrThreatLanguage = fearRules.filter((w) => lower.includes(w));
  const authorityImpersonation = authorityRules.filter((w) => lower.includes(w));
  const rewardOrLotteryScam = rewardRules.filter((w) => lower.includes(w));
  const credentialHarvestingRequests = credentialRules.filter((w) => lower.includes(w));
  const financialOrPaymentRequests = financialRules.filter((w) => lower.includes(w));

  const detectedScamPatterns: string[] = [];
  if (
    (fearOrThreatLanguage.length > 0 || urgencyIndicators.length > 0) &&
    credentialHarvestingRequests.length > 0
  ) {
    detectedScamPatterns.push('Credential Harvesting / Account Suspension Phishing');
  }
  if (
    lower.includes('otp') &&
    (lower.includes('share') || lower.includes('enter') || lower.includes('verify'))
  ) {
    detectedScamPatterns.push('OTP / 2FA Interception Request');
  }
  if (
    (lower.includes('delivery') || lower.includes('package') || lower.includes('parcel')) &&
    (lower.includes('fee') || lower.includes('address') || lower.includes('reschedule'))
  ) {
    detectedScamPatterns.push('Fake Package Delivery / Customs Fee Smishing');
  }
  if (rewardOrLotteryScam.length > 0) {
    detectedScamPatterns.push('Reward / Lottery / Giveaway Lure');
  }
  if (
    financialOrPaymentRequests.length > 0 &&
    (urgencyIndicators.length > 0 || authorityImpersonation.length > 0)
  ) {
    detectedScamPatterns.push('Urgent Financial / Payment Coercion');
  }
  if (
    lower.includes('kyc') &&
    (lower.includes('update') || lower.includes('expire') || lower.includes('suspend'))
  ) {
    detectedScamPatterns.push('Fake Banking KYC Suspension Scam');
  }

  const rawPoints =
    urgencyIndicators.length * 10 +
    fearOrThreatLanguage.length * 14 +
    authorityImpersonation.length * 10 +
    rewardOrLotteryScam.length * 14 +
    credentialHarvestingRequests.length * 16 +
    financialOrPaymentRequests.length * 12;

  const manipulationScore = Math.min(100, rawPoints);

  return {
    urgencyIndicators,
    fearOrThreatLanguage,
    authorityImpersonation,
    rewardOrLotteryScam,
    credentialHarvestingRequests,
    financialOrPaymentRequests,
    detectedScamPatterns,
    manipulationScore,
  };
}

interface GeminiVisionExtraction {
  available: boolean;
  extractedText: string;
  ocrClarity: 'High' | 'Partial' | 'NoText';
  screenshotCategory: string;
  detectedBrand: string | null;
  visualAddressBarUrl: string | null;
  containsLoginForm: boolean;
  containsPasswordInput: boolean;
  containsOtpInput: boolean;
  containsPaymentCardInput: boolean;
  containsUrgencyBanner: boolean;
  containsFakeAddressBar: boolean;
  containsDownloadPrompt: boolean;
  visualIndicators: string[];
  uiAuthenticityAssessment: string;
}

/**
 * Use Gemini Multimodal Vision (gemini-3.8-flash) to perform high-accuracy OCR and Visual UI Phishing Inspection
 */
async function performGeminiMultimodalInspection(
  buffer: Buffer,
  mimeType: string
): Promise<GeminiVisionExtraction> {
  const ai = getGenAIClient();
  if (!ai) {
    return {
      available: false,
      extractedText: '',
      ocrClarity: 'NoText',
      screenshotCategory: 'Unavailable (GEMINI_API_KEY not configured)',
      detectedBrand: null,
      visualAddressBarUrl: null,
      containsLoginForm: false,
      containsPasswordInput: false,
      containsOtpInput: false,
      containsPaymentCardInput: false,
      containsUrgencyBanner: false,
      containsFakeAddressBar: false,
      containsDownloadPrompt: false,
      visualIndicators: [],
      uiAuthenticityAssessment: 'Visual AI inspection unavailable without GEMINI_API_KEY.',
    };
  }

  try {
    const base64Data = buffer.toString('base64');
    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: [
        {
          inlineData: {
            data: base64Data,
            mimeType,
          },
        },
        {
          text: `You are a Senior Cybersecurity Visual & OCR Forensics Engine for PHISHING SHIELD.
Inspect this uploaded screenshot carefully and return a JSON object with:
1. "extractedText": Exact, verbatim transcription of ALL visible text in the image (including any browser address bar URL, sender address, phone number, message body, button labels, fine print). Do NOT invent or guess illegible text. If no text is visible, return "".
2. "ocrClarity": "High" if all text is clearly readable, "Partial" if some text is blurry/cut-off/low-resolution, or "NoText" if the image contains no text.
3. "screenshotCategory": Classify the screenshot (e.g., "Login / Credential Page", "SMS / WhatsApp Message", "Email Notification", "Banking / Payment Alert", "QR Code Promotion", "Customer Support Chat", "Social Media / Giveaway Post", "Government / Tax Notice", "General Screenshot").
4. "detectedBrand": If the screenshot visually displays a specific brand logo or name (e.g., "PayPal", "Microsoft", "Google", "Apple", "Amazon", "Netflix", "Chase", "SBI", "HDFC", "DHL", "FedEx", "USPS", "Coinbase", "MetaMask", "WhatsApp", "Instagram", "IRS"), state the brand name; otherwise return "".
5. "visualAddressBarUrl": If a browser URL address bar is visible in the screenshot, extract the exact URL or domain shown in the address bar; otherwise return "".
6. Boolean visual flags:
   - "containsLoginForm": true if a username/email/sign-in form is shown
   - "containsPasswordInput": true if a password input field is shown
   - "containsOtpInput": true if an OTP, 2FA, PIN, or verification code input is shown
   - "containsPaymentCardInput": true if credit/debit card, CVV, or payment transfer approval UI is shown
   - "containsUrgencyBanner": true if red/warning banners, countdown timers, or account suspension alerts are shown
   - "containsFakeAddressBar": true if a fake/spoofed address bar image or suspicious URL bar is visible
   - "containsDownloadPrompt": true if an APK/EXE/file download or software update prompt is shown
7. "visualIndicators": Array of 2 to 6 concrete visual observations about the UI layout, typography, branding, input fields, or suspicious cues.
8. "uiAuthenticityAssessment": Concise 1-2 sentence forensic assessment of the visual interface.`,
        },
      ],
      config: {
        temperature: 0.1,
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            extractedText: { type: Type.STRING },
            ocrClarity: { type: Type.STRING },
            screenshotCategory: { type: Type.STRING },
            detectedBrand: { type: Type.STRING },
            visualAddressBarUrl: { type: Type.STRING },
            containsLoginForm: { type: Type.BOOLEAN },
            containsPasswordInput: { type: Type.BOOLEAN },
            containsOtpInput: { type: Type.BOOLEAN },
            containsPaymentCardInput: { type: Type.BOOLEAN },
            containsUrgencyBanner: { type: Type.BOOLEAN },
            containsFakeAddressBar: { type: Type.BOOLEAN },
            containsDownloadPrompt: { type: Type.BOOLEAN },
            visualIndicators: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            uiAuthenticityAssessment: { type: Type.STRING },
          },
          required: [
            'extractedText',
            'ocrClarity',
            'screenshotCategory',
            'detectedBrand',
            'visualAddressBarUrl',
            'containsLoginForm',
            'containsPasswordInput',
            'containsOtpInput',
            'containsPaymentCardInput',
            'containsUrgencyBanner',
            'containsFakeAddressBar',
            'containsDownloadPrompt',
            'visualIndicators',
            'uiAuthenticityAssessment',
          ],
        },
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    const clarity: 'High' | 'Partial' | 'NoText' =
      parsed.ocrClarity === 'Partial'
        ? 'Partial'
        : parsed.ocrClarity === 'NoText'
          ? 'NoText'
          : 'High';

    return {
      available: true,
      extractedText: typeof parsed.extractedText === 'string' ? parsed.extractedText.trim() : '',
      ocrClarity: clarity,
      screenshotCategory: parsed.screenshotCategory || 'General Screenshot',
      detectedBrand:
        typeof parsed.detectedBrand === 'string' && parsed.detectedBrand.trim()
          ? parsed.detectedBrand.trim()
          : null,
      visualAddressBarUrl:
        typeof parsed.visualAddressBarUrl === 'string' && parsed.visualAddressBarUrl.trim()
          ? parsed.visualAddressBarUrl.trim()
          : null,
      containsLoginForm: Boolean(parsed.containsLoginForm),
      containsPasswordInput: Boolean(parsed.containsPasswordInput),
      containsOtpInput: Boolean(parsed.containsOtpInput),
      containsPaymentCardInput: Boolean(parsed.containsPaymentCardInput),
      containsUrgencyBanner: Boolean(parsed.containsUrgencyBanner),
      containsFakeAddressBar: Boolean(parsed.containsFakeAddressBar),
      containsDownloadPrompt: Boolean(parsed.containsDownloadPrompt),
      visualIndicators: Array.isArray(parsed.visualIndicators) ? parsed.visualIndicators : [],
      uiAuthenticityAssessment:
        parsed.uiAuthenticityAssessment || 'Completed multimodal visual UI inspection.',
    };
  } catch (error) {
    console.warn('Gemini Multimodal Vision fallback triggered:', formatGeminiErrorMessage(error));
    return {
      available: false,
      extractedText: '',
      ocrClarity: 'NoText',
      screenshotCategory: 'Unavailable',
      detectedBrand: null,
      visualAddressBarUrl: null,
      containsLoginForm: false,
      containsPasswordInput: false,
      containsOtpInput: false,
      containsPaymentCardInput: false,
      containsUrgencyBanner: false,
      containsFakeAddressBar: false,
      containsDownloadPrompt: false,
      visualIndicators: [],
      uiAuthenticityAssessment: `Visual AI inspection unavailable (${formatGeminiErrorMessage(error)}).`,
    };
  }
}

/**
 * Fallback OCR using local Tesseract.js if Gemini Vision is unavailable
 */
async function performLocalTesseractOcr(buffer: Buffer): Promise<{
  text: string;
  confidence: number;
  available: boolean;
}> {
  try {
    const Tesseract = await import('tesseract.js');
    const result = await Tesseract.recognize(buffer, 'eng');
    const text = result?.data?.text?.trim() || '';
    const confidence = typeof result?.data?.confidence === 'number' ? result.data.confidence : 0;
    return {
      text,
      confidence,
      available: true,
    };
  } catch {
    return {
      text: '',
      confidence: 0,
      available: false,
    };
  }
}

/**
 * Detect brand references in OCR text if visual brand detection wasn't already triggered
 */
function detectBrandFromText(text: string): string | null {
  const lower = text.toLowerCase();
  for (const brand of Object.keys(KNOWN_BRAND_DOMAINS)) {
    const regex = new RegExp(`\\b${brand}\\b`, 'i');
    if (regex.test(lower)) {
      return brand.charAt(0).toUpperCase() + brand.slice(1);
    }
  }
  return null;
}

/**
 * Generate Gemini AI Security Explanation specifically tailored to Screenshot Security Analysis
 */
async function generateScreenshotAiExplanation(params: {
  targetName: string;
  riskScore: number;
  verdict: ScreenshotRiskClassification;
  screenshotCategory: string;
  extractedTextSnippet: string;
  brandImpersonation: BrandImpersonationAnalysis;
  qrCode: QrCodeAnalysisResult;
  urlAnalyses: ExtractedUrlScanSummary[];
  socialEngineering: SocialEngineeringScreenshotAnalysis;
  visualIndicators: string[];
  evidence: EvidenceIndicator[];
}): Promise<AIExplanationResult> {
  const ai = getGenAIClient();
  if (!ai) {
    return {
      available: false,
      executiveSummary:
        'LLM explanation unavailable (GEMINI_API_KEY not configured). Review the deterministic OCR, QR, URL, and Visual evidence breakdown below.',
      technicalAssessment: 'Not Checked',
      keyFindings: params.evidence.slice(0, 5).map((e) => `${e.indicator}: ${e.value} (${e.details})`),
      recommendations: [
        {
          priority: params.riskScore >= 51 ? 'Immediate' : 'Standard',
          action: 'Do not enter passwords, OTPs, or payment details on links or QR codes from untrusted screenshots.',
          rationale: 'Prevents credential harvesting and unauthorized account takeover.',
        },
      ],
    };
  }

  try {
    const prompt = `You are a Senior SOC Threat Intelligence Analyst for PHISHING SHIELD.
Analyze the following REAL Screenshot Security Scan telemetry.
Target File: ${params.targetName}
Screenshot Category: ${params.screenshotCategory}
Calculated Risk Score: ${params.riskScore}/100 (${params.verdict})

Observed Evidence & Telemetry JSON:
${JSON.stringify(
  {
    extractedTextSnippet: params.extractedTextSnippet.slice(0, 1500),
    visualIndicators: params.visualIndicators,
    brandImpersonation: params.brandImpersonation,
    qrCode: {
      detected: params.qrCode.detected,
      decodedContent: params.qrCode.decodedContent,
      payloadType: params.qrCode.payloadType,
    },
    extractedUrlsAnalyzed: params.urlAnalyses.map((u) => ({
      url: u.url,
      source: u.source,
      registeredDomain: u.registeredDomain,
      usesHttps: u.usesHttps,
      domainAge: u.domainAge,
      resolvedIp: u.resolvedIp,
      brandMismatchWithVisual: u.brandMismatchWithVisual,
      riskScore: u.riskScore,
      verdict: u.verdict,
    })),
    socialEngineering: params.socialEngineering,
    evidence: params.evidence,
  },
  null,
  2
)}

CRITICAL RULES:
1. Base your explanation STRICTLY on the real observed OCR text, visual indicators, QR payload, and URL/DNS/RDAP telemetry above.
2. Never invent signals that were not observed. Remember that domain age alone does not make a domain malicious.
3. Explain clearly:
   - What type of screenshot this appears to be
   - Why it was classified as ${params.verdict} (${params.riskScore}/100)
   - Which visual, text, brand, QR, or URL indicators were found
   - Concrete, practical steps the user should take next.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        temperature: 0.2,
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            executiveSummary: { type: Type.STRING },
            technicalAssessment: { type: Type.STRING },
            keyFindings: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            recommendations: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  priority: { type: Type.STRING },
                  action: { type: Type.STRING },
                  rationale: { type: Type.STRING },
                },
                required: ['priority', 'action', 'rationale'],
              },
            },
          },
          required: ['executiveSummary', 'technicalAssessment', 'keyFindings', 'recommendations'],
        },
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    return {
      available: true,
      executiveSummary: parsed.executiveSummary || 'Screenshot analysis complete.',
      technicalAssessment: parsed.technicalAssessment || 'Technical assessment complete.',
      keyFindings: Array.isArray(parsed.keyFindings) ? parsed.keyFindings : [],
      recommendations: Array.isArray(parsed.recommendations)
        ? parsed.recommendations.map((r: any) => ({
            priority:
              r.priority === 'Immediate' || r.priority === 'High' ? r.priority : 'Standard',
            action: String(r.action || ''),
            rationale: String(r.rationale || ''),
          }))
        : [],
    };
  } catch (error) {
    return {
      available: false,
      executiveSummary: `Gemini explanation unavailable: ${formatGeminiErrorMessage(error)}`,
      technicalAssessment: 'Unavailable',
      keyFindings: params.evidence.slice(0, 5).map((e) => `${e.indicator}: ${e.value}`),
      recommendations: [],
    };
  }
}

/**
 * Main Screenshot Security Analyzer Pipeline
 */
export async function analyzeScreenshotImage(params: {
  buffer: Buffer;
  originalName: string;
  mimeType: string;
}): Promise<ScreenshotAnalysisResult> {
  const { buffer, originalName, mimeType } = params;

  // 1. Validate binary image format and dimensions using sharp
  let sharpMeta: SharpMetadata;
  try {
    sharpMeta = await sharp(buffer).metadata();
  } catch {
    throw new Error(
      'Uploaded file is not a valid or readable image buffer. Only valid PNG, JPG/JPEG, and WEBP images are accepted.'
    );
  }

  const allowedFormats = new Set(['png', 'jpeg', 'jpg', 'webp']);
  const detectedFormat = (sharpMeta.format || '').toLowerCase();
  if (!allowedFormats.has(detectedFormat)) {
    throw new Error(
      `Unsupported image format "${detectedFormat || 'unknown'}". Only PNG, JPG/JPEG, and WEBP screenshots are permitted.`
    );
  }

  const width = sharpMeta.width || 0;
  const height = sharpMeta.height || 0;
  if (width < 16 || height < 16) {
    throw new Error(`Image dimensions (${width}×${height}px) are too small for security analysis.`);
  }
  if (width > 8192 || height > 8192) {
    throw new Error(`Image dimensions (${width}×${height}px) exceed the 8192×8192px safety limit.`);
  }

  // 2. Extract EXIF metadata safely (if present)
  let exifData: Record<string, any> | null = null;
  try {
    exifData = await exifr.parse(buffer, {
      tiff: true,
      exif: true,
      gps: false,
    });
  } catch {
    exifData = null;
  }

  const exifSoftware = exifData?.Software ? String(exifData.Software).slice(0, 80) : 'Not Present';
  const exifMake = exifData?.Make ? String(exifData.Make) : '';
  const exifModel = exifData?.Model ? String(exifData.Model) : '';
  const exifDeviceMakeModel =
    `${exifMake} ${exifModel}`.trim().slice(0, 80) || 'Not Present';
  const rawExifDate = exifData?.DateTimeOriginal || exifData?.CreateDate || exifData?.ModifyDate;
  const exifDateTime =
    rawExifDate instanceof Date
      ? rawExifDate.toISOString().split('T')[0]
      : typeof rawExifDate === 'string'
        ? rawExifDate.slice(0, 32)
        : 'Not Present';

  const metadataReport: ImageMetadataReport = {
    fileName: originalName.slice(0, 120),
    mimeType,
    format: detectedFormat.toUpperCase(),
    fileSizeBytes: buffer.byteLength,
    formattedFileSize: formatBytes(buffer.byteLength),
    width,
    height,
    dimensions: `${width} × ${height} px`,
    colorSpace: sharpMeta.space ? sharpMeta.space.toUpperCase() : 'SRGB',
    channels: sharpMeta.channels || 3,
    hasAlpha: Boolean(sharpMeta.hasAlpha),
    exifAvailable: Boolean(
      exifData && (exifData.Software || exifData.Make || exifData.Model || rawExifDate)
    ),
    exifSoftware,
    exifDeviceMakeModel,
    exifDateTime,
  };

  // 3. Run QR Code Detection AND Gemini Multimodal OCR/Visual Inspection in parallel
  const [qrDetection, visionResult] = await Promise.all([
    detectAndDecodeQrCode(buffer),
    performGeminiMultimodalInspection(buffer, mimeType),
  ]);

  // 4. Determine OCR Text & Fallback to local Tesseract.js if Gemini Vision wasn't available
  let extractedText = visionResult.extractedText;
  let ocrEngine = 'Gemini 3.8 Multimodal Vision OCR';
  let ocrStatus: 'Extracted' | 'Partial / Low Clarity' | 'No Text Found' | 'Unavailable' =
    visionResult.available
      ? visionResult.ocrClarity === 'Partial'
        ? 'Partial / Low Clarity'
        : extractedText.length > 0
          ? 'Extracted'
          : 'No Text Found'
      : 'Unavailable';
  let lowClarityNotice: string | null =
    visionResult.ocrClarity === 'Partial'
      ? 'Some text could not be reliably extracted due to image resolution, blur, or cropping.'
      : null;

  if (!visionResult.available) {
    const localOcr = await performLocalTesseractOcr(buffer);
    if (localOcr.available) {
      extractedText = localOcr.text;
      ocrEngine = 'Local Tesseract OCR Engine';
      if (!extractedText) {
        ocrStatus = 'No Text Found';
      } else if (localOcr.confidence < 65) {
        ocrStatus = 'Partial / Low Clarity';
        lowClarityNotice = 'Some text could not be reliably extracted.';
      } else {
        ocrStatus = 'Extracted';
      }
    }
  }

  // 5. Extract URLs, Domains, Emails, and Phone Numbers from OCR Text + Visual Address Bar + QR Code
  const entities = extractEntitiesFromText(extractedText);
  const candidateUrlsWithSource: { url: string; source: 'OCR Text' | 'QR Code' | 'Visual Address Bar' }[] = [];

  if (visionResult.visualAddressBarUrl) {
    const cleanVisualUrl = visionResult.visualAddressBarUrl.trim();
    const normalizedVisual = /^https?:\/\//i.test(cleanVisualUrl)
      ? cleanVisualUrl
      : `https://${cleanVisualUrl}`;
    candidateUrlsWithSource.push({ url: normalizedVisual, source: 'Visual Address Bar' });
  }

  for (const u of entities.urls) {
    if (!candidateUrlsWithSource.some((item) => item.url.toLowerCase() === u.toLowerCase())) {
      candidateUrlsWithSource.push({ url: u, source: 'OCR Text' });
    }
  }

  // Classify QR Code content
  let qrPayloadType: QrCodeAnalysisResult['payloadType'] = 'None';
  if (qrDetection.detected && qrDetection.decodedContent) {
    const q = qrDetection.decodedContent.trim();
    if (/^https?:\/\//i.test(q) || /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/.test(q)) {
      qrPayloadType = 'URL';
      const normalizedQrUrl = /^https?:\/\//i.test(q) ? q : `https://${q}`;
      if (
        !candidateUrlsWithSource.some(
          (item) => item.url.toLowerCase() === normalizedQrUrl.toLowerCase()
        )
      ) {
        candidateUrlsWithSource.unshift({ url: normalizedQrUrl, source: 'QR Code' });
      }
    } else if (/^upi:\/\/|^bitcoin:|^ethereum:|^paytmmp:/i.test(q)) {
      qrPayloadType = 'Payment / UPI URI';
    } else if (/^[a-zA-Z0-9+.-]+:\/\//.test(q)) {
      qrPayloadType = 'Deep Link';
    } else {
      qrPayloadType = 'Plain Text';
    }
  }

  // 6. Brand & Impersonation Detection
  const rawDetectedBrand = visionResult.detectedBrand || detectBrandFromText(extractedText);
  const normalizedBrandKey = rawDetectedBrand
    ? rawDetectedBrand.toLowerCase().replace(/[^a-z0-9]/g, '')
    : '';
  const officialDomains =
    normalizedBrandKey && KNOWN_BRAND_DOMAINS[normalizedBrandKey]
      ? KNOWN_BRAND_DOMAINS[normalizedBrandKey]
      : [];

  // 7. Run Real URL Security Analysis on up to top 3 extracted URLs
  const urlsToScan = candidateUrlsWithSource.slice(0, 3);
  const urlAnalyses: ExtractedUrlScanSummary[] = [];

  for (const item of urlsToScan) {
    try {
      const urlRes = await analyzeUrlTarget(item.url);
      const regDomain = urlRes.domainAnalysis.registeredDomain.toLowerCase();

      // Check Brand vs Domain mismatch
      let brandMismatchWithVisual: string | null = null;
      if (rawDetectedBrand && officialDomains.length > 0) {
        const isOfficial = officialDomains.some(
          (d) => regDomain === d || regDomain.endsWith(`.${d}`)
        );
        if (!isOfficial) {
          brandMismatchWithVisual = `Visual screenshot displays "${rawDetectedBrand}" branding, but the extracted URL points to unverified domain "${regDomain}" (official: ${officialDomains.slice(0, 2).join(', ')}).`;
        }
      }

      urlAnalyses.push({
        url: urlRes.url,
        source: item.source,
        registeredDomain: urlRes.domainAnalysis.registeredDomain,
        tld: urlRes.domainAnalysis.tld,
        usesHttps: urlRes.syntax.usesHttps,
        domainAge: urlRes.domainAnalysis.rdap.formattedAge,
        creationDate: urlRes.domainAnalysis.rdap.creationDate,
        registrar: urlRes.domainAnalysis.rdap.registrar,
        resolvedIp: urlRes.ipAnalysis?.ip || 'Unresolved',
        ipOrganization: urlRes.ipAnalysis?.organization || 'Unavailable',
        ipCountry: urlRes.ipAnalysis?.country || 'Unavailable',
        dnsResolvable: urlRes.dnsAnalysis.resolvable,
        spfRecord: urlRes.dnsAnalysis.spfRecord,
        dmarcRecord: urlRes.dnsAnalysis.dmarcRecord,
        isShortener: urlRes.syntax.isUrlShortener,
        isIpHostname: urlRes.syntax.isIpHostname,
        isPunycode: urlRes.syntax.isPunycode,
        suspiciousKeywords: urlRes.syntax.suspiciousKeywords,
        homographIndicators: urlRes.syntax.homographIndicators,
        brandMismatchWithVisual,
        riskScore: urlRes.riskScore,
        verdict: urlRes.verdict,
        threatIntelligence: urlRes.threatIntelligence,
        evidence: urlRes.evidence,
      });
    } catch {
      // Skip unparseable URL candidate
    }
  }

  // Finalize Brand Impersonation summary
  const mismatchedUrls = urlAnalyses.filter((u) => Boolean(u.brandMismatchWithVisual));
  let impersonationRisk: BrandImpersonationAnalysis['impersonationRisk'] = 'None Detected';
  let mismatchDetails = 'No brand-to-domain impersonation conflict detected.';

  if (mismatchedUrls.length > 0) {
    impersonationRisk = 'High-Confidence Impersonation';
    mismatchDetails = mismatchedUrls[0].brandMismatchWithVisual!;
  } else if (rawDetectedBrand) {
    if (
      urlAnalyses.length === 0 &&
      (visionResult.containsLoginForm ||
        visionResult.containsPasswordInput ||
        visionResult.containsOtpInput ||
        visionResult.containsPaymentCardInput)
    ) {
      impersonationRisk = 'Possible Brand Reference';
      mismatchDetails = `Screenshot displays "${rawDetectedBrand}" branding alongside sensitive credential/payment inputs, but no verifiable official domain URL is visible.`;
    } else if (urlAnalyses.length > 0) {
      impersonationRisk = 'None Detected';
      mismatchDetails = `Detected brand "${rawDetectedBrand}" matches the analyzed domain (${urlAnalyses[0].registeredDomain}).`;
    } else {
      impersonationRisk = 'Possible Brand Reference';
      mismatchDetails = `Brand "${rawDetectedBrand}" is referenced in the screenshot without an associated URL.`;
    }
  }

  const brandImpersonation: BrandImpersonationAnalysis = {
    detectedBrand: rawDetectedBrand,
    officialDomains,
    impersonationRisk,
    brandDomainMismatch: mismatchedUrls.length > 0,
    mismatchDetails,
  };

  // 8. Finalize QR Code Analysis Result
  const qrUrlAnalysis = urlAnalyses.find((u) => u.source === 'QR Code') || null;
  let qrRiskSummary = 'No QR code detected in the uploaded screenshot.';
  if (qrDetection.detected && qrDetection.decodedContent) {
    if (qrUrlAnalysis) {
      qrRiskSummary = `QR code decodes to URL (${qrUrlAnalysis.url}) with risk score ${qrUrlAnalysis.riskScore}/100 (${qrUrlAnalysis.verdict}).`;
    } else if (qrPayloadType === 'Payment / UPI URI') {
      qrRiskSummary =
        'QR code encodes a direct Payment / UPI URI. Scanning to "receive" money is a common payment reversal scam—scanning a payment QR only authorizes outgoing funds.';
    } else {
      qrRiskSummary = `QR code decoded (${qrPayloadType}): ${qrDetection.decodedContent.slice(0, 120)}`;
    }
  }

  const qrCodeResult: QrCodeAnalysisResult = {
    checked: true,
    detected: qrDetection.detected,
    decodedContent: qrDetection.decodedContent,
    payloadType: qrPayloadType,
    urlAnalysis: qrUrlAnalysis,
    riskSummary: qrRiskSummary,
  };

  // 9. Run Social Engineering Analysis on Extracted Text + Visual Cues
  const socialEngineering = analyzeScreenshotSocialEngineering(
    extractedText,
    visionResult.visualIndicators
  );

  // 10. Visual Security Inspection Summary
  const textLower = extractedText.toLowerCase();
  const containsLoginForm =
    visionResult.containsLoginForm ||
    /\b(sign in|log in|login|username|email address)\b/i.test(textLower);
  const containsPasswordInput =
    visionResult.containsPasswordInput || /\b(password|passcode)\b/i.test(textLower);
  const containsOtpInput =
    visionResult.containsOtpInput ||
    /\b(otp|verification code|one-time password|2fa|security code)\b/i.test(textLower);
  const containsPaymentCardInput =
    visionResult.containsPaymentCardInput ||
    /\b(card number|cvv|expiry date|upi pin|wire transfer|pay now)\b/i.test(textLower);
  const containsUrgencyBanner =
    visionResult.containsUrgencyBanner ||
    socialEngineering.urgencyIndicators.length > 0 ||
    socialEngineering.fearOrThreatLanguage.length > 0;

  const visualInspection: VisualSecurityInspection = {
    available: visionResult.available,
    engine: visionResult.available
      ? 'Gemini 3.8 Multimodal Visual Inspector'
      : 'Heuristic OCR UI Inspector (Fallback)',
    screenshotCategory:
      visionResult.screenshotCategory !== 'Unavailable' &&
      !visionResult.screenshotCategory.startsWith('Unavailable')
        ? visionResult.screenshotCategory
        : containsLoginForm || containsPasswordInput
          ? 'Login / Credential Page'
          : qrDetection.detected
            ? 'QR Code Screenshot'
            : containsPaymentCardInput
              ? 'Payment / Financial Screen'
              : 'Message / Notification Screenshot',
    containsLoginForm,
    containsPasswordInput,
    containsOtpInput,
    containsPaymentCardInput,
    containsUrgencyBanner,
    containsFakeAddressBar: visionResult.containsFakeAddressBar,
    containsDownloadPrompt: visionResult.containsDownloadPrompt,
    visualIndicators:
      visionResult.visualIndicators.length > 0
        ? visionResult.visualIndicators
        : [
            containsPasswordInput ? 'Password / credential prompt detected in text' : '',
            containsOtpInput ? 'OTP / verification code prompt detected' : '',
            containsPaymentCardInput ? 'Payment / financial input indicators detected' : '',
            qrDetection.detected ? 'Embedded QR code matrix detected in screenshot' : '',
          ].filter(Boolean),
    uiAuthenticityAssessment: visionResult.uiAuthenticityAssessment,
  };

  // 11. Transparent Evidence-Based Risk Scoring Engine (0 - 100)
  const evidence: EvidenceIndicator[] = [];
  let riskScore = 0;

  // A. Extracted URL Risk Contribution
  if (urlAnalyses.length > 0) {
    const highestUrl = [...urlAnalyses].sort((a, b) => b.riskScore - a.riskScore)[0];
    const urlContribution = Math.round(highestUrl.riskScore * 0.65);
    evidence.push({
      category: 'Extracted URL Analysis',
      indicator: `URL Security Verdict (${highestUrl.source})`,
      value: `${highestUrl.registeredDomain} — Score ${highestUrl.riskScore}/100 (${highestUrl.verdict})`,
      impact:
        highestUrl.riskScore >= 50
          ? 'critical'
          : highestUrl.riskScore >= 25
            ? 'warning'
            : 'positive',
      scoreDelta: urlContribution,
      details: `HTTPS: ${highestUrl.usesHttps ? 'Yes' : 'No'}, Domain Age: ${highestUrl.domainAge}, IP: ${highestUrl.resolvedIp}.`,
    });
    riskScore += urlContribution;
  } else {
    evidence.push({
      category: 'Extracted URL Analysis',
      indicator: 'Embedded URLs in Screenshot',
      value: 'None Detected',
      impact: 'neutral',
      scoreDelta: 0,
      details: 'No actionable HTTP/HTTPS URLs or domain links were found in OCR or QR data.',
    });
  }

  // B. Brand Impersonation & Domain Mismatch
  if (brandImpersonation.brandDomainMismatch) {
    evidence.push({
      category: 'Brand Impersonation',
      indicator: 'Visual Brand vs. URL Domain Mismatch',
      value: `${brandImpersonation.detectedBrand} ≠ ${urlAnalyses[0]?.registeredDomain || 'Unknown'}`,
      impact: 'critical',
      scoreDelta: 35,
      details: brandImpersonation.mismatchDetails,
    });
    riskScore += 35;
  } else if (brandImpersonation.impersonationRisk === 'Possible Brand Reference') {
    const delta = containsPasswordInput || containsOtpInput || containsPaymentCardInput ? 18 : 6;
    evidence.push({
      category: 'Brand Impersonation',
      indicator: 'Unverified Brand Reference',
      value: brandImpersonation.detectedBrand || 'Detected',
      impact: delta >= 15 ? 'warning' : 'neutral',
      scoreDelta: delta,
      details: brandImpersonation.mismatchDetails,
    });
    riskScore += delta;
  } else if (brandImpersonation.detectedBrand) {
    evidence.push({
      category: 'Brand Impersonation',
      indicator: 'Brand Domain Alignment',
      value: `${brandImpersonation.detectedBrand} Verified`,
      impact: 'positive',
      scoreDelta: 0,
      details: brandImpersonation.mismatchDetails,
    });
  }

  // C. QR Code Security Assessment
  if (qrCodeResult.detected) {
    if (qrPayloadType === 'Payment / UPI URI') {
      evidence.push({
        category: 'QR Code Forensics',
        indicator: 'Payment / UPI Collect QR Code',
        value: 'Direct Payment URI Detected',
        impact: 'critical',
        scoreDelta: 28,
        details: qrCodeResult.riskSummary,
      });
      riskScore += 28;
    } else if (qrUrlAnalysis && qrUrlAnalysis.riskScore >= 25) {
      evidence.push({
        category: 'QR Code Forensics',
        indicator: 'Suspicious URL Encoded in QR Code',
        value: qrUrlAnalysis.registeredDomain,
        impact: qrUrlAnalysis.riskScore >= 50 ? 'critical' : 'warning',
        scoreDelta: 20,
        details: `Quishing (QR phishing) risk: QR code redirects to ${qrUrlAnalysis.url}.`,
      });
      riskScore += 20;
    } else {
      evidence.push({
        category: 'QR Code Forensics',
        indicator: 'QR Code Decoded',
        value: qrPayloadType,
        impact: 'neutral',
        scoreDelta: 5,
        details: qrCodeResult.riskSummary,
      });
      riskScore += 5;
    }
  }

  // D. Visual UI Credential / Financial Harvesting Signals
  const sensitiveInputs: string[] = [];
  if (containsPasswordInput) sensitiveInputs.push('Password Input');
  if (containsOtpInput) sensitiveInputs.push('OTP / 2FA Code Input');
  if (containsPaymentCardInput) sensitiveInputs.push('Payment / Card Input');
  if (containsLoginForm && sensitiveInputs.length === 0) sensitiveInputs.push('Sign-In Form');

  if (sensitiveInputs.length > 0) {
    const hasSuspiciousContext =
      brandImpersonation.brandDomainMismatch ||
      socialEngineering.manipulationScore >= 20 ||
      urlAnalyses.some((u) => u.riskScore >= 25);
    const uiDelta = hasSuspiciousContext ? 22 : 10;
    evidence.push({
      category: 'Visual Security Analysis',
      indicator: 'Sensitive Credential / Financial UI Elements',
      value: sensitiveInputs.join(', '),
      impact: hasSuspiciousContext ? 'critical' : 'warning',
      scoreDelta: uiDelta,
      details: `Screenshot solicits sensitive user input (${sensitiveInputs.join(', ')}).`,
    });
    riskScore += uiDelta;
  }

  if (visionResult.containsFakeAddressBar || visionResult.containsDownloadPrompt) {
    evidence.push({
      category: 'Visual Security Analysis',
      indicator: 'Deceptive UI / Download Prompt',
      value: visionResult.containsFakeAddressBar
        ? 'Spoofed Address Bar Indicator'
        : 'Executable / APK Download Prompt',
      impact: 'critical',
      scoreDelta: 25,
      details: 'Visual inspection flagged deceptive browser chrome or untrusted software download prompt.',
    });
    riskScore += 25;
  }

  // E. Social Engineering & Scam Language Signals
  if (socialEngineering.detectedScamPatterns.length > 0 || socialEngineering.manipulationScore > 0) {
    const seDelta = Math.min(35, Math.round(socialEngineering.manipulationScore * 0.45));
    if (seDelta > 0) {
      evidence.push({
        category: 'Social Engineering Analysis',
        indicator: 'Psychological Manipulation & Scam Patterns',
        value:
          socialEngineering.detectedScamPatterns.length > 0
            ? socialEngineering.detectedScamPatterns.join('; ')
            : `Manipulation Score ${socialEngineering.manipulationScore}/100`,
        impact: seDelta >= 20 ? 'critical' : 'warning',
        scoreDelta: seDelta,
        details: [
          socialEngineering.urgencyIndicators.length > 0
            ? `Urgency: ${socialEngineering.urgencyIndicators.join(', ')}`
            : '',
          socialEngineering.fearOrThreatLanguage.length > 0
            ? `Fear/Threat: ${socialEngineering.fearOrThreatLanguage.join(', ')}`
            : '',
          socialEngineering.credentialHarvestingRequests.length > 0
            ? `Credential Cues: ${socialEngineering.credentialHarvestingRequests.join(', ')}`
            : '',
          socialEngineering.financialOrPaymentRequests.length > 0
            ? `Financial Cues: ${socialEngineering.financialOrPaymentRequests.join(', ')}`
            : '',
          socialEngineering.rewardOrLotteryScam.length > 0
            ? `Reward Lure: ${socialEngineering.rewardOrLotteryScam.join(', ')}`
            : '',
        ]
          .filter(Boolean)
          .join(' | '),
      });
      riskScore += seDelta;
    }
  } else {
    evidence.push({
      category: 'Social Engineering Analysis',
      indicator: 'Coercive / Scam Language Cues',
      value: 'None Detected',
      impact: 'positive',
      scoreDelta: 0,
      details: 'No high-pressure urgency, fear threats, or lottery/OTP coercion detected in text.',
    });
  }

  riskScore = Math.max(0, Math.min(100, Math.round(riskScore)));

  const verdict: ScreenshotRiskClassification =
    riskScore >= 76
      ? 'CRITICAL RISK'
      : riskScore >= 51
        ? 'HIGH RISK'
        : riskScore >= 21
          ? 'MEDIUM RISK'
          : 'LOW RISK';

  // Calculate confidence score based on available engines and clarity
  let confidenceScore = 88;
  if (!visionResult.available) confidenceScore -= 14;
  if (ocrStatus === 'Partial / Low Clarity') confidenceScore -= 12;
  if (ocrStatus === 'No Text Found' && !qrCodeResult.detected) confidenceScore -= 15;

  // Aggregate Threat Intelligence feeds across analyzed URLs
  const threatIntelligence: ExternalFeedStatus[] =
    urlAnalyses.length > 0
      ? urlAnalyses[0].threatIntelligence
      : [
          {
            source: 'Abuse.ch URLhaus Database',
            status: 'Not Checked',
            details: 'No URL was extracted from the screenshot to query against URLhaus.',
          },
          {
            source: 'Spamhaus ZEN / Barracuda DNSBL',
            status: 'Not Checked',
            details: 'No domain/IP was extracted from the screenshot.',
          },
        ];

  const aiExplanation = await generateScreenshotAiExplanation({
    targetName: originalName,
    riskScore,
    verdict,
    screenshotCategory: visualInspection.screenshotCategory,
    extractedTextSnippet: extractedText,
    brandImpersonation,
    qrCode: qrCodeResult,
    urlAnalyses,
    socialEngineering,
    visualIndicators: visualInspection.visualIndicators,
    evidence,
  });

  const lineCount = extractedText
    ? extractedText.split(/\r?\n/).filter((l) => l.trim().length > 0).length
    : 0;

  return {
    scanType: 'screenshot',
    targetName: originalName,
    riskScore,
    verdict,
    confidenceScore: Math.max(40, Math.min(99, confidenceScore)),
    metadata: metadataReport,
    ocr: {
      status: ocrStatus,
      engine: ocrEngine,
      extractedText,
      lowClarityNotice,
      characterCount: extractedText.length,
      lineCount,
      extractedUrls: candidateUrlsWithSource.map((c) => c.url),
      extractedDomains: entities.domains,
      extractedEmails: entities.emails,
      extractedPhones: entities.phones,
    },
    qrCode: qrCodeResult,
    visualInspection,
    brandImpersonation,
    socialEngineering,
    urlAnalyses,
    threatIntelligence,
    evidence,
    aiExplanation,
    scannedAt: new Date().toISOString(),
  };
}

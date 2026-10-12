import type { EvidenceIndicator } from './ipAnalyzer.ts';
import { analyzeUrlTarget } from './urlAnalyzer.ts';
import { generateSecurityExplanation, type AIExplanationResult } from './geminiService.ts';

interface NlpPatternGroup {
  category: string;
  severity: 'warning' | 'critical';
  weight: number;
  patterns: { label: string; regex: RegExp }[];
}

const NLP_PATTERN_GROUPS: NlpPatternGroup[] = [
  {
    category: 'Urgency & Coercion Tactics',
    severity: 'warning',
    weight: 16,
    patterns: [
      { label: 'Immediate action demand', regex: /\b(immediate(ly)?\s+action|act\s+now|urgent\s+notice|within\s+24\s+hours|within\s+48\s+hours|final\s+warning|expires?\s+today)\b/i },
      { label: 'Account suspension threat', regex: /\b(account\s+(will\s+be\s+|has\s+been\s+)?(suspended|locked|terminated|deactivated|restricted|closed)|unusual\s+sign-?in\s+activity)\b/i },
      { label: 'Unauthorized access alarm', regex: /\b(unauthorized\s+(login|access|transaction|attempt)|security\s+alert|compromised\s+account)\b/i },
    ],
  },
  {
    category: 'Credential & MFA Harvesting',
    severity: 'critical',
    weight: 26,
    patterns: [
      { label: 'Password / Login verification prompt', regex: /\b(verify\s+your\s+(password|account|identity|credentials)|confirm\s+your\s+(identity|login|details)|update\s+your\s+security\s+info)\b/i },
      { label: 'OTP / 2FA / PIN harvesting', regex: /\b(one-?time\s+(passcode|password|code)|6-?digit\s+code|verification\s+code|share\s+the\s+code|enter\s+your\s+pin|social\s+security\s+number|ssn)\b/i },
      { label: 'Crypto seed phrase request', regex: /\b(seed\s+phrase|recovery\s+phrase|12-?word|24-?word|private\s+key|connect\s+your\s+wallet)\b/i },
    ],
  },
  {
    category: 'Financial & Payment Diversion Lures',
    severity: 'critical',
    weight: 24,
    patterns: [
      { label: 'Wire transfer / Invoice urgency', regex: /\b(overdue\s+invoice|wire\s+transfer|updated\s+bank(ing)?\s+details|ach\s+routing|unpaid\s+balance|payment\s+failed|billing\s+error)\b/i },
      { label: 'Gift card / Crypto coercion', regex: /\b(gift\s+cards?|apple\s+cards?|steam\s+cards?|bitcoin\s+atm|usdt|wallet\s+address)\b/i },
      { label: 'Package / Customs fee lure', regex: /\b(delivery\s+failed|customs\s+fee|shipping\s+fee|redelivery|parcel\s+held|tracking\s+update)\b/i },
    ],
  },
  {
    category: 'Impersonation & Generic Salutation',
    severity: 'warning',
    weight: 12,
    patterns: [
      { label: 'Generic non-personalized greeting', regex: /\b(dear\s+(valued\s+)?(customer|user|member|client|account\s+holder))\b/i },
      { label: 'Executive / IT Helpdesk authority claim', regex: /\b(it\s+helpdesk|security\s+operations\s+team|ceo|chief\s+executive|payroll\s+department|hr\s+department|internal\s+revenue)\b/i },
    ],
  },
];

export interface MessageAnalysisResult {
  messageLength: number;
  wordCount: number;
  senderInput: string;
  extractedEntities: {
    urls: string[];
    emails: string[];
    phoneNumbers: string[];
    domains: string[];
  };
  headerAnalysis: {
    provided: boolean;
    spfStatus: string;
    dkimStatus: string;
    dmarcStatus: string;
    replyToMismatch: boolean;
    details: string;
  };
  nlpSignals: {
    category: string;
    matchedPhrases: string[];
    severity: 'warning' | 'critical';
  }[];
  manipulationVectorScores: {
    urgency: number;
    authority: number;
    fearAndCoercion: number;
    credentialHarvesting: number;
    financialLure: number;
  };
  embeddedUrlScan: Awaited<ReturnType<typeof analyzeUrlTarget>> | null;
  mlClassification: {
    phishingConfidence: number;
    primaryIntent: string;
  };
  riskScore: number;
  verdict: 'Clean' | 'Low Risk' | 'Suspicious' | 'High Risk' | 'Malicious';
  evidence: EvidenceIndicator[];
  aiExplanation?: AIExplanationResult;
  scannedAt: string;
}

export async function analyzeMessageContent(
  rawMessage: string,
  senderAddress?: string,
  rawHeaders?: string
): Promise<MessageAnalysisResult> {
  const text = rawMessage.trim();
  if (!text) {
    throw new Error('Message content cannot be empty.');
  }

  const words = text.split(/\s+/).filter(Boolean);
  const urlRegex = /https?:\/\/[^\s<>"')]+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|edu|gov|io|co|xyz|top|info|biz|me|us|uk|ca|de|jp|fr|au|in|ru|ch|it|nl|se|no|es|mil|app|dev|link|click|work|online|site|tech|store|shop)(?:\/[^\s<>"')]*)?/gi;
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const phoneRegex = /(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g;

  const emails = Array.from(new Set(text.match(emailRegex) || []));
  const rawUrlMatches = Array.from(new Set(text.match(urlRegex) || []));
  // Exclude matched emails from rawUrlMatches
  const urls = rawUrlMatches.filter(
    (u) => !emails.some((em) => em.toLowerCase().includes(u.toLowerCase()))
  );
  const phoneNumbers = Array.from(new Set(text.match(phoneRegex) || []));

  const domains = Array.from(
    new Set(
      urls
        .map((u) => {
          try {
            const normalized = /^https?:\/\//i.test(u) ? u : `https://${u}`;
            return new URL(normalized).hostname.toLowerCase();
          } catch {
            return '';
          }
        })
        .filter(Boolean)
    )
  );

  const evidence: EvidenceIndicator[] = [];
  let riskScore = 0;

  // Evaluate NLP Pattern Groups
  const nlpSignals: {
    category: string;
    matchedPhrases: string[];
    severity: 'warning' | 'critical';
  }[] = [];

  for (const group of NLP_PATTERN_GROUPS) {
    const matched: string[] = [];
    for (const pat of group.patterns) {
      const m = text.match(pat.regex);
      if (m && m[0]) {
        matched.push(`${pat.label} ("${m[0]}")`);
      }
    }
    if (matched.length > 0) {
      nlpSignals.push({
        category: group.category,
        matchedPhrases: matched,
        severity: group.severity,
      });
      const delta = Math.min(group.weight + (matched.length - 1) * 6, 35);
      riskScore += delta;
      evidence.push({
        category: 'NLP Message Analysis',
        indicator: group.category,
        value: `${matched.length} signal(s) detected`,
        impact: group.severity,
        scoreDelta: delta,
        details: matched.join('; '),
      });
    }
  }

  if (nlpSignals.length === 0) {
    evidence.push({
      category: 'NLP Message Analysis',
      indicator: 'Linguistic Manipulation Patterns',
      value: 'None Detected',
      impact: 'positive',
      scoreDelta: 0,
      details: 'No coercive urgency, credential harvesting, or financial diversion phrases matched.',
    });
  }

  // Evaluate Sender & Optional Headers
  let spfStatus = 'Not Checked';
  let dkimStatus = 'Not Checked';
  let dmarcStatus = 'Not Checked';
  let replyToMismatch = false;
  let headerDetails = 'No raw email headers provided for cryptographic inspection.';

  if (rawHeaders && rawHeaders.trim()) {
    const hdr = rawHeaders;
    const spfMatch = hdr.match(/spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i);
    const dkimMatch = hdr.match(/dkim=(pass|fail|neutral|none|policy|temperror|permerror)/i);
    const dmarcMatch = hdr.match(/dmarc=(pass|fail|bestguesspass|none)/i);

    spfStatus = spfMatch ? spfMatch[1].toUpperCase() : 'Not Present in Header';
    dkimStatus = dkimMatch ? dkimMatch[1].toUpperCase() : 'Not Present in Header';
    dmarcStatus = dmarcMatch ? dmarcMatch[1].toUpperCase() : 'Not Present in Header';

    const fromMatch = hdr.match(/^From:\s*(.+)$/im);
    const replyToMatch = hdr.match(/^Reply-To:\s*(.+)$/im);
    if (fromMatch && replyToMatch) {
      const fromEmail = fromMatch[1].match(emailRegex)?.[0]?.toLowerCase();
      const replyEmail = replyToMatch[1].match(emailRegex)?.[0]?.toLowerCase();
      if (fromEmail && replyEmail && fromEmail !== replyEmail) {
        replyToMismatch = true;
      }
    }

    headerDetails = `Parsed Authentication-Results: SPF=${spfStatus}, DKIM=${dkimStatus}, DMARC=${dmarcStatus}`;

    if (spfStatus === 'FAIL' || spfStatus === 'SOFTFAIL' || dkimStatus === 'FAIL' || dmarcStatus === 'FAIL') {
      riskScore += 30;
      evidence.push({
        category: 'Email Header Authentication',
        indicator: 'SPF / DKIM / DMARC Alignment Failure',
        value: `SPF: ${spfStatus}, DKIM: ${dkimStatus}, DMARC: ${dmarcStatus}`,
        impact: 'critical',
        scoreDelta: 30,
        details: 'Message failed sender authentication checks in headers.',
      });
    } else if (spfStatus === 'PASS' || dkimStatus === 'PASS' || dmarcStatus === 'PASS') {
      evidence.push({
        category: 'Email Header Authentication',
        indicator: 'SPF / DKIM / DMARC Alignment',
        value: `SPF: ${spfStatus}, DKIM: ${dkimStatus}, DMARC: ${dmarcStatus}`,
        impact: 'positive',
        scoreDelta: 0,
        details: 'Email authentication headers report passing verification.',
      });
    }

    if (replyToMismatch) {
      riskScore += 20;
      evidence.push({
        category: 'Email Header Authentication',
        indicator: 'From vs. Reply-To Address Mismatch',
        value: 'Mismatch Detected',
        impact: 'warning',
        scoreDelta: 20,
        details: 'The Reply-To header directs replies to a different address than the From header.',
      });
    }
  }

  // Check Sender Address display name vs domain mismatch
  if (senderAddress && senderAddress.trim()) {
    const s = senderAddress.trim();
    const freemailDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com', 'icloud.com'];
    const senderEmailMatch = s.match(emailRegex)?.[0]?.toLowerCase() || s.toLowerCase();
    const senderDomain = senderEmailMatch.includes('@') ? senderEmailMatch.split('@')[1] : '';

    if (
      senderDomain &&
      freemailDomains.includes(senderDomain) &&
      /\b(paypal|microsoft|apple|amazon|google|bank|chase|wellsfargo|support|security|billing|dhl|fedex|usps|netflix)\b/i.test(
        s + ' ' + text
      )
    ) {
      riskScore += 28;
      evidence.push({
        category: 'Sender Identity',
        indicator: 'Brand Claim Sent from Consumer Freemail Domain',
        value: `${s} (${senderDomain})`,
        impact: 'critical',
        scoreDelta: 28,
        details: `Message claims corporate/institutional authority while originating from a public freemail domain (${senderDomain}).`,
      });
    } else {
      evidence.push({
        category: 'Sender Identity',
        indicator: 'Declared Sender',
        value: s,
        impact: 'neutral',
        scoreDelta: 0,
        details: 'Sender address recorded for correlation.',
      });
    }
  }

  // Live-inspect the first embedded URL if present!
  let embeddedUrlScan: Awaited<ReturnType<typeof analyzeUrlTarget>> | null = null;
  if (urls.length > 0) {
    try {
      embeddedUrlScan = await analyzeUrlTarget(urls[0]);
      const urlContribution = Math.round(embeddedUrlScan.riskScore * 0.55);
      riskScore += urlContribution;
      evidence.push({
        category: 'Embedded URL Inspection',
        indicator: `Live Scan of Embedded Link (${urls[0]})`,
        value: `URL Risk Score: ${embeddedUrlScan.riskScore}/100 (${embeddedUrlScan.verdict})`,
        impact:
          embeddedUrlScan.riskScore >= 50
            ? 'critical'
            : embeddedUrlScan.riskScore >= 25
              ? 'warning'
              : 'positive',
        scoreDelta: urlContribution,
        details: `Domain ${embeddedUrlScan.domainAnalysis.registeredDomain} (Age: ${embeddedUrlScan.domainAnalysis.rdap.formattedAge}).`,
      });
    } catch {
      evidence.push({
        category: 'Embedded URL Inspection',
        indicator: 'Embedded Link Syntax',
        value: urls[0],
        impact: 'warning',
        scoreDelta: 10,
        details: 'Message contains an embedded link that could not be cleanly parsed.',
      });
      riskScore += 10;
    }
  }

  riskScore = Math.max(0, Math.min(100, riskScore));
  const verdict =
    riskScore >= 75
      ? 'Malicious'
      : riskScore >= 50
        ? 'High Risk'
        : riskScore >= 25
          ? 'Suspicious'
          : riskScore >= 10
            ? 'Low Risk'
            : 'Clean';

  const hasUrgency = nlpSignals.some((s) => s.category === 'Urgency & Coercion Tactics');
  const hasCreds = nlpSignals.some((s) => s.category === 'Credential & MFA Harvesting');
  const hasFinance = nlpSignals.some((s) => s.category === 'Financial & Payment Diversion Lures');
  const hasAuthority = nlpSignals.some((s) => s.category === 'Impersonation & Generic Salutation');

  const manipulationVectorScores = {
    urgency: hasUrgency ? 85 : /\b(soon|today|please|asap|reminder)\b/i.test(text) ? 35 : 5,
    authority: hasAuthority ? 80 : senderAddress ? 25 : 10,
    fearAndCoercion: hasUrgency ? 82 : 8,
    credentialHarvesting: hasCreds ? 92 : urls.length > 0 ? 30 : 5,
    financialLure: hasFinance ? 88 : 5,
  };

  const primaryIntent = hasCreds
    ? 'Credential / MFA Harvesting Phish'
    : hasFinance
      ? 'Business Email Compromise / Financial Fraud'
      : hasUrgency && urls.length > 0
        ? 'Coercive Link-Click Lure'
        : riskScore < 25
          ? 'Benign / Informational Communication'
          : 'Suspicious Social Engineering Attempt';

  const aiExplanation = await generateSecurityExplanation(
    'message',
    text.slice(0, 300),
    riskScore,
    verdict,
    {
      senderInput: senderAddress || 'Not Provided',
      wordCount: words.length,
      extractedUrls: urls,
      extractedEmails: emails,
      extractedPhoneNumbers: phoneNumbers,
      headerAnalysis: {
        provided: Boolean(rawHeaders && rawHeaders.trim()),
        spfStatus,
        dkimStatus,
        dmarcStatus,
        replyToMismatch,
      },
      nlpSignals,
      manipulationVectorScores,
      embeddedUrlVerdict: embeddedUrlScan
        ? {
            url: embeddedUrlScan.url,
            riskScore: embeddedUrlScan.riskScore,
            verdict: embeddedUrlScan.verdict,
            domainAge: embeddedUrlScan.domainAnalysis.rdap.formattedAge,
          }
        : 'No URL in message',
      evidence,
    }
  );

  return {
    messageLength: text.length,
    wordCount: words.length,
    senderInput: senderAddress || 'Not Provided',
    extractedEntities: {
      urls,
      emails,
      phoneNumbers,
      domains,
    },
    headerAnalysis: {
      provided: Boolean(rawHeaders && rawHeaders.trim()),
      spfStatus,
      dkimStatus,
      dmarcStatus,
      replyToMismatch,
      details: headerDetails,
    },
    nlpSignals,
    manipulationVectorScores,
    embeddedUrlScan,
    mlClassification: {
      phishingConfidence: riskScore,
      primaryIntent,
    },
    riskScore,
    verdict,
    evidence,
    aiExplanation,
    scannedAt: new Date().toISOString(),
  };
}

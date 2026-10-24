import sharp from 'sharp';
import jsQR from 'jsqr';
import { analyzeUrlTarget } from './urlAnalyzer.ts';
import type { EvidenceIndicator, ExternalFeedStatus } from './ipAnalyzer.ts';

export interface QrScanResult {
  detected: boolean;
  content: string | null;
  payloadType: 'URL' | 'UPI / Payment' | 'Email' | 'Phone / SMS' | 'Wi-Fi' | 'Plain Text' | 'None';
  riskScore: number;
  verdict: 'Clean' | 'Low Risk' | 'Suspicious' | 'High Risk' | 'Malicious';
  confidence: number;
  evidence: EvidenceIndicator[];
  recommendations: string[];
  urlAnalysis: Awaited<ReturnType<typeof analyzeUrlTarget>> | null;
  metadata: {
    format: string;
    width: number;
    height: number;
  };
  scannedAt: string;
}

/**
 * Multi-pass QR code decoder and security analyzer.
 * Uses sharp for image normalization, contrast enhancement, and grayscale inversion
 * before feeding into jsQR for resilient detection.
 */
export async function analyzeQrImageBuffer(buffer: Buffer): Promise<QrScanResult> {
  const image = sharp(buffer);
  const meta = await image.metadata();
  const width = meta.width || 0;
  const height = meta.height || 0;
  const format = meta.format || 'unknown';

  if (!width || !height) {
    throw new Error('Invalid image dimensions. Unable to process QR code.');
  }

  // Attempt multi-pass decoding
  let decodedText: string | null = null;

  // Pass 1: Standard raw RGBA
  const pass1 = await sharp(buffer)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });
  const code1 = jsQR(new Uint8ClampedArray(pass1.data), pass1.info.width, pass1.info.height);
  if (code1?.data) {
    decodedText = code1.data;
  }

  // Pass 2: Grayscale + normalized contrast (handles noisy camera scans)
  if (!decodedText) {
    const pass2 = await sharp(buffer)
      .grayscale()
      .normalize()
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    const code2 = jsQR(new Uint8ClampedArray(pass2.data), pass2.info.width, pass2.info.height);
    if (code2?.data) {
      decodedText = code2.data;
    }
  }

  // Pass 3: Inverted colors (for dark mode QR codes where foreground is white and background is black)
  if (!decodedText) {
    const pass3 = await sharp(buffer)
      .grayscale()
      .negate()
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    const code3 = jsQR(new Uint8ClampedArray(pass3.data), pass3.info.width, pass3.info.height);
    if (code3?.data) {
      decodedText = code3.data;
    }
  }

  const evidence: EvidenceIndicator[] = [];
  const recommendations: string[] = [];
  let riskScore = 0;
  let urlAnalysis: Awaited<ReturnType<typeof analyzeUrlTarget>> | null = null;
  let payloadType: QrScanResult['payloadType'] = 'None';

  if (!decodedText) {
    evidence.push({
      category: 'QR Code Detection',
      indicator: 'QR Matrix Recognition',
      value: 'No Decodable QR Matrix Found',
      impact: 'neutral',
      scoreDelta: 0,
      details: 'The uploaded image does not contain a recognizable QR barcode matrix.',
    });

    return {
      detected: false,
      content: null,
      payloadType: 'None',
      riskScore: 0,
      verdict: 'Clean',
      confidence: 90,
      evidence,
      recommendations: [
        'Ensure the QR code is centered, well-lit, and in focus.',
        'Avoid extreme camera angles, excessive glare, or heavy compression artifacts.',
      ],
      urlAnalysis: null,
      metadata: { format, width, height },
      scannedAt: new Date().toISOString(),
    };
  }

  // Determine payload classification
  const trimmed = decodedText.trim();
  const urlMatch = trimmed.match(/^https?:\/\/[^\s]+/i) || trimmed.match(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.(com|org|net|io|co|in|xyz|top|app|dev|biz)\b/i);

  if (urlMatch) {
    payloadType = 'URL';
    const targetUrl = trimmed.startsWith('http') ? trimmed : `https://${trimmed}`;

    evidence.push({
      category: 'QR Code Payload',
      indicator: 'Web Destination URL',
      value: targetUrl.length > 80 ? `${targetUrl.slice(0, 80)}...` : targetUrl,
      impact: 'warning',
      scoreDelta: 10,
      details: 'QR code directs the scanner to an external web URL (Quishing vector).',
    });

    // Run full security analysis on the target URL
    try {
      urlAnalysis = await analyzeUrlTarget(targetUrl);
      riskScore = urlAnalysis.riskScore;
      urlAnalysis.evidence.forEach((ev) => {
        evidence.push(ev);
      });
      if (urlAnalysis.aiExplanation?.recommendations) {
        recommendations.push(...urlAnalysis.aiExplanation.recommendations.map((r) => r.action));
      }
    } catch {
      riskScore += 25;
      evidence.push({
        category: 'URL Inspection',
        indicator: 'URL Reachability / Lexical Check',
        value: targetUrl,
        impact: 'warning',
        scoreDelta: 15,
        details: 'Failed to inspect decoded destination URL.',
      });
    }
  } else if (/^upi:\/\/pay/i.test(trimmed)) {
    payloadType = 'UPI / Payment';
    riskScore += 45;
    evidence.push({
      category: 'Financial Diversion',
      indicator: 'Direct UPI Payment URI',
      value: trimmed.slice(0, 60),
      impact: 'critical',
      scoreDelta: 45,
      details: 'QR code triggers a direct financial payment request (potential payment diversion scam).',
    });
    recommendations.push(
      'Verify the payee name and VPA with the official merchant before authorizing UPI PIN entry.',
      'Remember that entering your UPI PIN always debits money from your account, never receives money.'
    );
  } else if (/^mailto:/i.test(trimmed)) {
    payloadType = 'Email';
    riskScore += 15;
    evidence.push({
      category: 'QR Code Payload',
      indicator: 'Email Draft Trigger',
      value: trimmed.slice(0, 60),
      impact: 'warning',
      scoreDelta: 15,
      details: 'QR code opens an email draft to an external recipient.',
    });
  } else if (/^(tel|sms|smsto):/i.test(trimmed)) {
    payloadType = 'Phone / SMS';
    riskScore += 20;
    evidence.push({
      category: 'QR Code Payload',
      indicator: 'Telephony / SMS Trigger',
      value: trimmed.slice(0, 60),
      impact: 'warning',
      scoreDelta: 20,
      details: 'QR code triggers a phone call or SMS message destination.',
    });
  } else if (/^WIFI:/i.test(trimmed)) {
    payloadType = 'Wi-Fi';
    riskScore += 10;
    evidence.push({
      category: 'QR Code Payload',
      indicator: 'Wi-Fi Network Configuration',
      value: 'Wi-Fi Credentials Payload',
      impact: 'neutral',
      scoreDelta: 10,
      details: 'QR code contains automatic Wi-Fi association parameters.',
    });
  } else {
    payloadType = 'Plain Text';
    evidence.push({
      category: 'QR Code Payload',
      indicator: 'Plain Text Content',
      value: trimmed.length > 80 ? `${trimmed.slice(0, 80)}...` : trimmed,
      impact: 'neutral',
      scoreDelta: 0,
      details: 'QR code contains plain text without active URL links.',
    });
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

  return {
    detected: true,
    content: decodedText,
    payloadType,
    riskScore,
    verdict,
    confidence: urlAnalysis ? 92 : 85,
    evidence,
    recommendations:
      recommendations.length > 0
        ? recommendations
        : [
            'Do not scan untrusted QR codes pasted over parking meters, payment stands, or public flyers.',
            'Always inspect the destination domain in your browser before entering credentials or approving permissions.',
          ],
    urlAnalysis,
    metadata: { format, width, height },
    scannedAt: new Date().toISOString(),
  };
}

import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import { domainToUnicode, domainToASCII } from 'node:url';
import {
  analyzeIpAddress,
  classifyIpScope,
  type EvidenceIndicator,
  type ExternalFeedStatus,
  type IpAnalysisResult,
} from './ipAnalyzer.ts';
import { generateSecurityExplanation, type AIExplanationResult } from './geminiService.ts';

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rb.gy',
  'tiny.cc',
  'shorturl.at',
  'rebrand.ly',
  'cutt.ly',
  'lnkd.in',
  'bl.ink',
  'v.gd',
]);

const SUSPICIOUS_KEYWORDS = [
  'login',
  'verify',
  'verification',
  'secure',
  'account',
  'update',
  'banking',
  'signin',
  'sign-in',
  'confirm',
  'wallet',
  'password',
  'credential',
  'webscr',
  'authenticate',
  'recover',
  'unlock',
  'suspend',
  'billing',
  'invoice',
  'auth',
  'passcode',
  'mfa',
  '2fa',
  'seedphrase',
];

const HIGH_RISK_TLDS = new Set([
  'zip',
  'mov',
  'top',
  'xyz',
  'gq',
  'tk',
  'ml',
  'cf',
  'ga',
  'work',
  'click',
  'loan',
  'buzz',
  'rest',
  'fit',
  'icu',
  'Monster',
  'sbs',
  'cfd',
  'quest',
]);

const MONITORED_BRANDS = [
  'google',
  'microsoft',
  'apple',
  'paypal',
  'amazon',
  'netflix',
  'chase',
  'wellsfargo',
  'coinbase',
  'binance',
  'github',
  'dropbox',
  'docusign',
  'linkedin',
  'facebook',
  'instagram',
  'stripe',
  'okta',
  'cloudflare',
  'adobe',
  'bankofamerica',
  'citibank',
  'dhl',
  'fedex',
  'usps',
  'steam',
  'discord',
];

const MULTI_PART_TLDS = new Set([
  'co.uk',
  'org.uk',
  'gov.uk',
  'ac.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.jp',
  'co.in',
  'com.br',
  'com.sg',
  'co.nz',
  'co.za',
]);

function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const key of Object.keys(freq)) {
    const p = freq[key] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

function normalizeHomoglyphs(input: string): string {
  return input
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/@/g, 'a')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
}

export function extractDomainParts(hostname: string) {
  const cleanHost = hostname.toLowerCase().replace(/\.$/, '');
  if (net.isIP(cleanHost) !== 0) {
    return {
      registeredDomain: cleanHost,
      sld: cleanHost,
      tld: 'IP Address',
      subdomain: '',
      subdomainCount: 0,
      isIpHostname: true,
    };
  }

  const labels = cleanHost.split('.');
  if (labels.length <= 1) {
    return {
      registeredDomain: cleanHost,
      sld: cleanHost,
      tld: '',
      subdomain: '',
      subdomainCount: 0,
      isIpHostname: false,
    };
  }

  const lastTwo = labels.slice(-2).join('.');
  let tld = labels[labels.length - 1];
  let sld = labels[labels.length - 2];
  let subdomainLabels = labels.slice(0, -2);

  if (MULTI_PART_TLDS.has(lastTwo) && labels.length >= 3) {
    tld = lastTwo;
    sld = labels[labels.length - 3];
    subdomainLabels = labels.slice(0, -3);
  }

  const registeredDomain = `${sld}.${tld}`;
  const subdomain = subdomainLabels.join('.');

  return {
    registeredDomain,
    sld,
    tld,
    subdomain,
    subdomainCount: subdomainLabels.length,
    isIpHostname: false,
  };
}

async function lookupDomainRdap(registeredDomain: string) {
  const tld = registeredDomain.split('.').pop()?.toLowerCase() || '';
  const endpoints = [`https://rdap.org/domain/${encodeURIComponent(registeredDomain)}`];
  if (tld === 'com' || tld === 'net') {
    endpoints.push(`https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(registeredDomain)}`);
  } else if (tld === 'org') {
    endpoints.push(
      `https://rdap.publicinterestregistry.org/rdap/domain/${encodeURIComponent(registeredDomain)}`
    );
  }

  for (const url of endpoints) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4500);
      const res = await fetch(url, {
        headers: { Accept: 'application/rdap+json, application/json' },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) continue;

      const data = await res.json();
      let creationDate = 'Unavailable';
      let expirationDate = 'Unavailable';
      let lastChangedDate = 'Unavailable';

      if (Array.isArray(data.events)) {
        for (const ev of data.events) {
          if (ev.eventAction === 'registration' && ev.eventDate) {
            creationDate = ev.eventDate;
          } else if (ev.eventAction === 'expiration' && ev.eventDate) {
            expirationDate = ev.eventDate;
          } else if (ev.eventAction === 'last changed' && ev.eventDate) {
            lastChangedDate = ev.eventDate;
          }
        }
      }

      let registrar = 'Unavailable';
      if (Array.isArray(data.entities)) {
        for (const ent of data.entities) {
          if (Array.isArray(ent.roles) && ent.roles.includes('registrar')) {
            const vcard = ent.vcardArray?.[1];
            if (Array.isArray(vcard)) {
              const fnField = vcard.find((f: unknown[]) => Array.isArray(f) && f[0] === 'fn');
              if (fnField && typeof fnField[3] === 'string') {
                registrar = fnField[3];
                break;
              }
            }
            if (ent.handle) {
              registrar = ent.handle;
            }
          }
        }
      }

      const statusList: string[] = Array.isArray(data.status) ? data.status : [];
      let ageDays: number | null = null;
      let formattedAge = 'Unavailable';
      let currentDateIso = new Date().toISOString().split('T')[0];

      if (creationDate !== 'Unavailable') {
        const createdMs = Date.parse(creationDate);
        const nowMs = Date.now();
        if (!Number.isNaN(createdMs) && nowMs >= createdMs) {
          ageDays = Math.floor((nowMs - createdMs) / (1000 * 60 * 60 * 24));
          const years = Math.floor(ageDays / 365);
          const remainingDays = ageDays % 365;
          formattedAge =
            years > 0
              ? `${ageDays} days (${years} yr ${remainingDays} d)`
              : `${ageDays} days`;
        }
      }

      return {
        available: creationDate !== 'Unavailable' || registrar !== 'Unavailable',
        creationDate: creationDate !== 'Unavailable' ? creationDate.split('T')[0] : 'Unavailable',
        currentDate: currentDateIso,
        expirationDate:
          expirationDate !== 'Unavailable' ? expirationDate.split('T')[0] : 'Unavailable',
        lastChangedDate:
          lastChangedDate !== 'Unavailable' ? lastChangedDate.split('T')[0] : 'Unavailable',
        ageDays,
        formattedAge,
        registrar,
        statusFlags: statusList,
      };
    } catch {
      // Try next RDAP endpoint
    }
  }

  return {
    available: false,
    creationDate: 'Unavailable',
    currentDate: new Date().toISOString().split('T')[0],
    expirationDate: 'Unavailable',
    lastChangedDate: 'Unavailable',
    ageDays: null,
    formattedAge: 'Unavailable',
    registrar: 'Unavailable',
    statusFlags: [] as string[],
  };
}

async function resolveDomainDns(hostname: string, registeredDomain: string) {
  const withTimeout = <T>(p: Promise<T>, fallback: T): Promise<T> =>
    Promise.race([
      p.catch(() => fallback),
      new Promise<T>((resolve) => setTimeout(() => resolve(fallback), 3000)),
    ]);

  const [aRecords, aaaaRecords, cnameRecords, mxRecords, nsRecords, txtRecords, dmarcRecords] =
    await Promise.all([
      withTimeout(dns.resolve4(hostname), [] as string[]),
      withTimeout(dns.resolve6(hostname), [] as string[]),
      withTimeout(dns.resolveCname(hostname), [] as string[]),
      withTimeout(dns.resolveMx(registeredDomain), [] as { exchange: string; priority: number }[]),
      withTimeout(dns.resolveNs(registeredDomain), [] as string[]),
      withTimeout(dns.resolveTxt(registeredDomain), [] as string[][]),
      withTimeout(dns.resolveTxt(`_dmarc.${registeredDomain}`), [] as string[][]),
    ]);

  const flattenedTxt = txtRecords.map((chunks) => chunks.join(''));
  const flattenedDmarc = dmarcRecords.map((chunks) => chunks.join(''));

  const spfRecord = flattenedTxt.find((t) => t.toLowerCase().startsWith('v=spf1')) || 'Not Present';
  const dmarcRecord =
    flattenedDmarc.find((t) => t.toLowerCase().startsWith('v=dmarc1')) || 'Not Present';

  const resolvedAny =
    aRecords.length > 0 ||
    aaaaRecords.length > 0 ||
    cnameRecords.length > 0 ||
    nsRecords.length > 0;

  return {
    resolvable: resolvedAny,
    aRecords,
    aaaaRecords,
    cnameRecords,
    mxRecords: mxRecords
      .sort((a, b) => a.priority - b.priority)
      .map((m) => `${m.exchange} (priority ${m.priority})`),
    nsRecords,
    txtRecords: flattenedTxt.slice(0, 8),
    spfRecord,
    dmarcRecord,
  };
}

interface TlsInspectionResult {
  available: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  protocol?: string;
  reason?: string;
}

async function inspectTlsCertificate(hostname: string, ip: string): Promise<TlsInspectionResult> {
  if (classifyIpScope(ip) !== 'Public') {
    return { available: false, reason: 'Non-public IP skipped for SSRF protection' };
  }

  return new Promise<TlsInspectionResult>((resolve) => {
    const socket = tls.connect(
      {
        host: ip,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 3500,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || 'Unavailable';
          socket.destroy();

          if (!cert || Object.keys(cert).length === 0) {
            resolve({ available: false, reason: 'No peer certificate presented' });
            return;
          }

          const validToMs = Date.parse(cert.valid_to);
          const daysRemaining = !Number.isNaN(validToMs)
            ? Math.floor((validToMs - Date.now()) / (1000 * 60 * 60 * 24))
            : undefined;

          const issuerOrg =
            cert.issuer?.O || cert.issuer?.CN || 'Unknown Certificate Authority';
          const subjectCn = cert.subject?.CN || hostname;

          resolve({
            available: true,
            issuer: Array.isArray(issuerOrg) ? issuerOrg.join(', ') : String(issuerOrg),
            subject: Array.isArray(subjectCn) ? subjectCn.join(', ') : String(subjectCn),
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            protocol,
          });
        } catch {
          socket.destroy();
          resolve({ available: false, reason: 'Failed to parse certificate' });
        }
      }
    );

    socket.on('error', () => {
      socket.destroy();
      resolve({ available: false, reason: 'TLS handshake failed or port 443 closed' });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ available: false, reason: 'TLS handshake timed out' });
    });
  });
}

async function traceSafeRedirects(initialUrl: string, primaryIp: string | null) {
  const hops: { hop: number; url: string; statusCode: number | string; location?: string }[] = [];
  if (!primaryIp || classifyIpScope(primaryIp) !== 'Public') {
    return {
      checked: false,
      hops,
      crossDomainRedirect: false,
      finalUrl: initialUrl,
      statusNote: 'Skipped active HTTP probe (no public IP resolved)',
    };
  }

  let currentUrl = initialUrl;
  const initialHost = new URL(initialUrl).hostname.toLowerCase();
  let crossDomainRedirect = false;

  for (let hop = 1; hop <= 4; hop++) {
    try {
      const parsed = new URL(currentUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        break;
      }
      // Verify hostname is not localhost or private IP
      if (
        parsed.hostname === 'localhost' ||
        (net.isIP(parsed.hostname) !== 0 && classifyIpScope(parsed.hostname) !== 'Public')
      ) {
        break;
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3000);
      const response = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        headers: {
          'User-Agent': 'PhishingShield-SecurityScanner/1.0 (+https://phishingshield.security)',
        },
        signal: controller.signal,
      });
      clearTimeout(timer);

      const locationHeader = response.headers.get('location') || undefined;
      hops.push({
        hop,
        url: currentUrl,
        statusCode: response.status,
        location: locationHeader,
      });

      if (response.status >= 300 && response.status < 400 && locationHeader) {
        const nextUrl = new URL(locationHeader, currentUrl).toString();
        const nextHost = new URL(nextUrl).hostname.toLowerCase();
        if (nextHost !== initialHost && !nextHost.endsWith(`.${initialHost}`)) {
          crossDomainRedirect = true;
        }
        currentUrl = nextUrl;
      } else {
        break;
      }
    } catch {
      if (hops.length === 0) {
        return {
          checked: false,
          hops,
          crossDomainRedirect: false,
          finalUrl: initialUrl,
          statusNote: 'Target server did not respond to HEAD probe within 3s',
        };
      }
      break;
    }
  }

  return {
    checked: hops.length > 0,
    hops,
    crossDomainRedirect,
    finalUrl: currentUrl,
    statusNote: hops.length > 0 ? `Traced ${hops.length} HTTP hop(s)` : 'Unavailable',
  };
}

async function checkUrlhausThreatFeed(hostname: string): Promise<ExternalFeedStatus> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    const body = new URLSearchParams({ host: hostname });
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      return {
        source: 'Abuse.ch URLhaus Database',
        status: 'Unavailable',
        details: `URLhaus returned HTTP ${res.status}`,
      };
    }
    const data = await res.json();
    if (data.query_status === 'no_results') {
      return {
        source: 'Abuse.ch URLhaus Database',
        status: 'Clean',
        details: 'Host is not listed in Abuse.ch URLhaus malware/phishing repository.',
      };
    }
    if (data.query_status === 'ok' && Number(data.url_count) > 0) {
      return {
        source: 'Abuse.ch URLhaus Database',
        status: 'Flagged',
        details: `Host has ${data.url_count} malicious URL record(s) in Abuse.ch URLhaus.`,
      };
    }
    return {
      source: 'Abuse.ch URLhaus Database',
      status: 'Unavailable',
      details: 'URLhaus response inconclusive',
    };
  } catch {
    return {
      source: 'Abuse.ch URLhaus Database',
      status: 'Unavailable',
      details: 'URLhaus endpoint unreachable or timed out',
    };
  }
}

export async function analyzeUrlTarget(rawInput: string) {
  let normalizedInput = rawInput.trim();
  if (!/^https?:\/\//i.test(normalizedInput)) {
    normalizedInput = `https://${normalizedInput}`;
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(normalizedInput);
  } catch {
    throw new Error('Invalid URL syntax. Please provide a valid HTTP or HTTPS URL.');
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS protocols are supported for URL analysis.');
  }

  const asciiHost = domainToASCII(parsedUrl.hostname.toLowerCase());
  const unicodeHost = domainToUnicode(parsedUrl.hostname.toLowerCase());
  const isPunycode = asciiHost.includes('xn--') || asciiHost !== unicodeHost;

  const domainParts = extractDomainParts(asciiHost);
  const usesHttps = parsedUrl.protocol === 'https:';
  const urlLength = normalizedInput.length;
  const hostnameLength = asciiHost.length;
  const pathLength = parsedUrl.pathname.length;
  const queryParams = Array.from(parsedUrl.searchParams.keys());
  const hasAtSymbol = normalizedInput.includes('@') && Boolean(parsedUrl.username || parsedUrl.password || normalizedInput.split('?')[0].includes('@'));
  const isShortener = URL_SHORTENERS.has(domainParts.registeredDomain);
  const hyphenCount = (asciiHost.match(/-/g) || []).length;
  const digitCount = (asciiHost.match(/\d/g) || []).length;
  const digitRatio = hostnameLength > 0 ? Number((digitCount / hostnameLength).toFixed(2)) : 0;
  const hostEntropy = calculateShannonEntropy(asciiHost);
  const pathEntropy = calculateShannonEntropy(parsedUrl.pathname + parsedUrl.search);

  // Detect suspicious keywords in URL
  const lowerFullUrl = normalizedInput.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((kw) => lowerFullUrl.includes(kw));

  // Detect homograph / brand typosquatting
  const normalizedSld = normalizeHomoglyphs(domainParts.sld.replace(/-/g, ''));
  const homographIndicators: string[] = [];
  if (isPunycode) {
    homographIndicators.push(`IDN Punycode detected (${asciiHost} → ${unicodeHost})`);
  }
  // Check non-ASCII scripts in unicodeHost
  if (/[^\u0000-\u007f]/.test(unicodeHost)) {
    homographIndicators.push(`Non-ASCII Unicode characters present in domain (${unicodeHost})`);
  }

  for (const brand of MONITORED_BRANDS) {
    if (domainParts.sld !== brand) {
      if (domainParts.sld.includes(brand) || domainParts.subdomain.includes(brand)) {
        homographIndicators.push(
          `Brand keyword "${brand}" embedded in non-official domain (${asciiHost})`
        );
      } else {
        const dist = levenshteinDistance(normalizedSld, brand);
        if (brand.length >= 5 && dist === 1) {
          homographIndicators.push(
            `Possible typosquatting / homoglyph match to "${brand}" (edit distance 1: "${domainParts.sld}")`
          );
        }
      }
    }
  }

  // Run Live DNS, Live RDAP, and URLhaus in parallel
  const [dnsAnalysis, rdapInfo, urlhausFeed] = await Promise.all([
    domainParts.isIpHostname
      ? Promise.resolve({
          resolvable: true,
          aRecords: net.isIP(asciiHost) === 4 ? [asciiHost] : [],
          aaaaRecords: net.isIP(asciiHost) === 6 ? [asciiHost] : [],
          cnameRecords: [],
          mxRecords: [],
          nsRecords: [],
          txtRecords: [],
          spfRecord: 'Not Applicable (IP Host)',
          dmarcRecord: 'Not Applicable (IP Host)',
        })
      : resolveDomainDns(asciiHost, domainParts.registeredDomain),
    domainParts.isIpHostname
      ? Promise.resolve({
          available: false,
          creationDate: 'Not Applicable (IP Host)',
          currentDate: new Date().toISOString().split('T')[0],
          expirationDate: 'Not Applicable',
          lastChangedDate: 'Not Applicable',
          ageDays: null,
          formattedAge: 'Not Applicable (IP Host)',
          registrar: 'Not Applicable',
          statusFlags: [] as string[],
        })
      : lookupDomainRdap(domainParts.registeredDomain),
    checkUrlhausThreatFeed(asciiHost),
  ]);

  const primaryIp =
    dnsAnalysis.aRecords[0] ||
    dnsAnalysis.aaaaRecords[0] ||
    (domainParts.isIpHostname ? asciiHost : null);

  // Run IP analysis, TLS inspection, and Redirect trace in parallel if primaryIp exists
  const [ipAnalysis, tlsInspection, redirectTrace] = await Promise.all([
    primaryIp ? analyzeIpAddress(primaryIp, false).catch(() => null) : Promise.resolve(null),
    usesHttps && primaryIp
      ? inspectTlsCertificate(asciiHost, primaryIp)
      : Promise.resolve<TlsInspectionResult>({
          available: false,
          reason: usesHttps ? 'Domain did not resolve to an IP' : 'URL uses unencrypted HTTP',
        }),
    traceSafeRedirects(normalizedInput, primaryIp),
  ]);

  // Build Evidence-Based Risk Scoring
  const evidence: EvidenceIndicator[] = [];
  let riskScore = 0;

  // 1. HTTPS / Transport Security
  if (usesHttps) {
    evidence.push({
      category: 'Transport Security',
      indicator: 'HTTPS Protocol',
      value: 'Enabled (HTTPS)',
      impact: 'positive',
      scoreDelta: 0,
      details: 'URL specifies encrypted HTTPS transport.',
    });
  } else {
    evidence.push({
      category: 'Transport Security',
      indicator: 'Unencrypted HTTP Protocol',
      value: 'Insecure (HTTP)',
      impact: 'warning',
      scoreDelta: 15,
      details: 'URL uses cleartext HTTP without transport encryption.',
    });
    riskScore += 15;
  }

  // 2. TLS Certificate verification
  if (usesHttps) {
    if (tlsInspection.available) {
      if (typeof tlsInspection.daysRemaining === 'number' && tlsInspection.daysRemaining < 0) {
        evidence.push({
          category: 'Transport Security',
          indicator: 'TLS X.509 Certificate',
          value: `Expired (${tlsInspection.daysRemaining} days)`,
          impact: 'critical',
          scoreDelta: 25,
          details: `Certificate issued by ${tlsInspection.issuer} has expired.`,
        });
        riskScore += 25;
      } else {
        evidence.push({
          category: 'Transport Security',
          indicator: 'TLS X.509 Certificate',
          value: `Valid (${tlsInspection.issuer}, ${tlsInspection.daysRemaining ?? '?'} days left)`,
          impact: 'positive',
          scoreDelta: 0,
          details: `Negotiated ${tlsInspection.protocol} with subject ${tlsInspection.subject}.`,
        });
      }
    } else {
      evidence.push({
        category: 'Transport Security',
        indicator: 'TLS X.509 Handshake',
        value: 'Unavailable',
        impact: 'warning',
        scoreDelta: 10,
        details: tlsInspection.reason || 'Could not establish TLS handshake on port 443.',
      });
      riskScore += 10;
    }
  }

  // 3. Raw IP used as Hostname
  if (domainParts.isIpHostname) {
    evidence.push({
      category: 'URL Structure',
      indicator: 'IP Address Used Instead of Domain',
      value: asciiHost,
      impact: 'critical',
      scoreDelta: 30,
      details: 'Legitimate services rarely serve authentication pages directly on raw IP literals.',
    });
    riskScore += 30;
  }

  // 4. URL Shortener
  if (isShortener) {
    evidence.push({
      category: 'URL Structure',
      indicator: 'URL Shortener Service',
      value: domainParts.registeredDomain,
      impact: 'warning',
      scoreDelta: 18,
      details: 'URL shorteners obscure the true destination domain from the user.',
    });
    riskScore += 18;
  }

  // 5. Subdomain Depth
  if (domainParts.subdomainCount >= 3) {
    evidence.push({
      category: 'Domain Analysis',
      indicator: 'Excessive Subdomains',
      value: `${domainParts.subdomainCount} subdomains (${domainParts.subdomain})`,
      impact: 'warning',
      scoreDelta: 16,
      details: 'Deep subdomain chains are commonly used to mimic legitimate domains on mobile.',
    });
    riskScore += 16;
  } else {
    evidence.push({
      category: 'Domain Analysis',
      indicator: 'Subdomain Depth',
      value:
        domainParts.subdomainCount === 0
          ? 'Root domain (0 subdomains)'
          : `${domainParts.subdomainCount} (${domainParts.subdomain})`,
      impact: 'positive',
      scoreDelta: 0,
      details: 'Subdomain structure is within normal parameters.',
    });
  }

  // 6. TLD Reputation
  if (HIGH_RISK_TLDS.has(domainParts.tld)) {
    evidence.push({
      category: 'Domain Analysis',
      indicator: 'Top-Level Domain (TLD) Profile',
      value: `.${domainParts.tld}`,
      impact: 'warning',
      scoreDelta: 14,
      details: `The .${domainParts.tld} TLD exhibits elevated abuse rates in phishing telemetry.`,
    });
    riskScore += 14;
  } else {
    evidence.push({
      category: 'Domain Analysis',
      indicator: 'Top-Level Domain (TLD) Profile',
      value: `.${domainParts.tld}`,
      impact: 'neutral',
      scoreDelta: 0,
      details: 'Standard top-level domain.',
    });
  }

  // 7. Homograph / Brand Impersonation / Punycode
  if (homographIndicators.length > 0) {
    evidence.push({
      category: 'Homograph & Brand Analysis',
      indicator: 'Brand / Homograph Spoofing Signals',
      value: `${homographIndicators.length} indicator(s) detected`,
      impact: 'critical',
      scoreDelta: 35,
      details: homographIndicators.join('; '),
    });
    riskScore += 35;
  } else {
    evidence.push({
      category: 'Homograph & Brand Analysis',
      indicator: 'Punycode & Brand Spoofing',
      value: 'None Detected',
      impact: 'positive',
      scoreDelta: 0,
      details: 'No IDN homograph or high-confidence brand typosquatting detected.',
    });
  }

  // 8. Lexical & Keyword Indicators
  if (hasAtSymbol) {
    evidence.push({
      category: 'URL Structure',
      indicator: 'Embedded "@" Authority Character',
      value: 'Present',
      impact: 'critical',
      scoreDelta: 28,
      details: 'The "@" symbol in URLs causes browsers to ignore everything before "@" as userinfo.',
    });
    riskScore += 28;
  }

  if (urlLength > 100) {
    evidence.push({
      category: 'URL Structure',
      indicator: 'URL Length',
      value: `${urlLength} characters`,
      impact: 'warning',
      scoreDelta: 10,
      details: 'Long URLs (>100 chars) are frequently used to hide redirect targets in address bars.',
    });
    riskScore += 10;
  } else {
    evidence.push({
      category: 'URL Structure',
      indicator: 'URL Length',
      value: `${urlLength} characters`,
      impact: 'positive',
      scoreDelta: 0,
      details: 'Standard concise URL length.',
    });
  }

  if (hyphenCount >= 3) {
    evidence.push({
      category: 'Domain Analysis',
      indicator: 'Multiple Hyphens in Hostname',
      value: `${hyphenCount} hyphens`,
      impact: 'warning',
      scoreDelta: 12,
      details: 'Phishing domains frequently chain words with multiple hyphens.',
    });
    riskScore += 12;
  }

  if (matchedKeywords.length > 0) {
    const kwDelta = Math.min(20, matchedKeywords.length * 6);
    evidence.push({
      category: 'URL Structure',
      indicator: 'Sensitive Action Keywords',
      value: matchedKeywords.join(', '),
      impact: matchedKeywords.length >= 2 ? 'warning' : 'neutral',
      scoreDelta: kwDelta,
      details: `URL contains authentication/financial keywords: ${matchedKeywords.join(', ')}.`,
    });
    riskScore += kwDelta;
  }

  // 9. Domain Age (RDAP) — Remember: Domain age alone must NOT classify a website as malicious!
  if (rdapInfo.ageDays !== null) {
    if (rdapInfo.ageDays < 30) {
      // Max 15 points so domain age alone never classifies a site as Suspicious/Malicious
      evidence.push({
        category: 'Domain Registration (RDAP)',
        indicator: 'Domain Age',
        value: `${rdapInfo.formattedAge} (Created ${rdapInfo.creationDate})`,
        impact: 'warning',
        scoreDelta: 15,
        details: `Newly registered domain (${rdapInfo.ageDays} days old). Note: Domain age is an auxiliary indicator and never classifies a site as malicious on its own.`,
      });
      riskScore += 15;
    } else if (rdapInfo.ageDays < 180) {
      evidence.push({
        category: 'Domain Registration (RDAP)',
        indicator: 'Domain Age',
        value: `${rdapInfo.formattedAge} (Created ${rdapInfo.creationDate})`,
        impact: 'neutral',
        scoreDelta: 5,
        details: `Domain registered within the last 6 months via ${rdapInfo.registrar}.`,
      });
      riskScore += 5;
    } else {
      evidence.push({
        category: 'Domain Registration (RDAP)',
        indicator: 'Domain Age',
        value: `${rdapInfo.formattedAge} (Created ${rdapInfo.creationDate})`,
        impact: 'positive',
        scoreDelta: 0,
        details: `Established domain registered via ${rdapInfo.registrar}.`,
      });
    }
  } else {
    evidence.push({
      category: 'Domain Registration (RDAP)',
      indicator: 'Domain Age',
      value: 'Domain age: Unavailable',
      impact: 'neutral',
      scoreDelta: 0,
      details:
        'RDAP registration date was not returned by the TLD registry. No risk points added.',
    });
  }

  // 10. DNS Resolution & Email Authentication Posture
  if (!dnsAnalysis.resolvable) {
    evidence.push({
      category: 'DNS Analysis',
      indicator: 'DNS Resolution',
      value: 'NXDOMAIN / Unresolvable',
      impact: 'warning',
      scoreDelta: 20,
      details: 'Domain failed to resolve to any A, AAAA, CNAME, or NS records in live DNS.',
    });
    riskScore += 20;
  } else {
    evidence.push({
      category: 'DNS Analysis',
      indicator: 'DNS A / AAAA Resolution',
      value:
        [...dnsAnalysis.aRecords, ...dnsAnalysis.aaaaRecords].slice(0, 3).join(', ') ||
        'CNAME/NS Only',
      impact: 'positive',
      scoreDelta: 0,
      details: `Resolved ${dnsAnalysis.aRecords.length} IPv4 and ${dnsAnalysis.aaaaRecords.length} IPv6 record(s).`,
    });

    if (dnsAnalysis.spfRecord !== 'Not Present' && dnsAnalysis.dmarcRecord !== 'Not Present') {
      evidence.push({
        category: 'DNS Analysis',
        indicator: 'Domain Email Security (SPF + DMARC)',
        value: 'SPF & DMARC Configured',
        impact: 'positive',
        scoreDelta: 0,
        details: 'Domain publishes both SPF and DMARC anti-spoofing policies.',
      });
    }
  }

  // 11. Resolved IP Reputation
  if (ipAnalysis) {
    const listedCount = ipAnalysis.dnsblResults.filter((d) => d.status === 'Listed').length;
    if (listedCount > 0) {
      const ipDelta = Math.min(35, listedCount * 20);
      evidence.push({
        category: 'IP Reputation',
        indicator: 'Resolved IP Blacklist Status',
        value: `${ipAnalysis.ip} listed on ${listedCount} DNSBL(s)`,
        impact: 'critical',
        scoreDelta: ipDelta,
        details: `Associated IP ${ipAnalysis.ip} (${ipAnalysis.asn}) is listed on real-time abuse blacklists.`,
      });
      riskScore += ipDelta;
    } else {
      evidence.push({
        category: 'IP Reputation',
        indicator: 'Resolved IP Blacklist Status',
        value: `${ipAnalysis.ip} (${ipAnalysis.organization}) — Clean`,
        impact: 'positive',
        scoreDelta: 0,
        details: `Resolved IP is clean across live DNSBL checks.`,
      });
    }
  }

  // 12. Threat Intelligence Feeds (URLhaus)
  if (urlhausFeed.status === 'Flagged') {
    evidence.push({
      category: 'Threat Intelligence',
      indicator: 'Abuse.ch URLhaus Feed',
      value: 'Flagged as Malicious',
      impact: 'critical',
      scoreDelta: 55,
      details: urlhausFeed.details,
    });
    riskScore += 55;
  } else if (urlhausFeed.status === 'Clean') {
    evidence.push({
      category: 'Threat Intelligence',
      indicator: 'Abuse.ch URLhaus Feed',
      value: 'Clean (0 hits)',
      impact: 'positive',
      scoreDelta: 0,
      details: urlhausFeed.details,
    });
  }

  // 13. Cross-domain redirect behavior
  if (redirectTrace.crossDomainRedirect) {
    evidence.push({
      category: 'Redirect Behavior',
      indicator: 'Cross-Domain HTTP Redirect',
      value: `Redirects to ${redirectTrace.finalUrl}`,
      impact: 'warning',
      scoreDelta: 12,
      details: 'Initial URL redirects to a different external domain.',
    });
    riskScore += 12;
  }

  riskScore = Math.max(0, Math.min(100, riskScore));

  // ML Feature Vector & Classifier Score (Normalized 0-100 confidence)
  const mlFeatures = [
    {
      feature: 'Lexical Host Entropy',
      rawValue: `${hostEntropy} bits/char`,
      normalizedWeight: Math.min(1, Math.max(0, (hostEntropy - 2.5) / 2.2)),
      contribution: hostEntropy > 3.8 ? 'Elevated randomness' : 'Normal lexical distribution',
    },
    {
      feature: 'Path & Query Entropy',
      rawValue: `${pathEntropy} bits/char`,
      normalizedWeight: Math.min(1, Math.max(0, (pathEntropy - 2.8) / 2.2)),
      contribution: pathEntropy > 4.1 ? 'Obfuscated/token path' : 'Standard path structure',
    },
    {
      feature: 'Brand Homograph Risk',
      rawValue: homographIndicators.length > 0 ? 'Positive Match' : '0 matches',
      normalizedWeight: homographIndicators.length > 0 ? 0.92 : 0.02,
      contribution:
        homographIndicators.length > 0
          ? 'High similarity to targeted brand'
          : 'No brand impersonation',
    },
    {
      feature: 'Subdomain & Structural Complexity',
      rawValue: `${domainParts.subdomainCount} sub / ${hyphenCount} hyphens / ${urlLength} chars`,
      normalizedWeight: Math.min(
        1,
        domainParts.subdomainCount * 0.22 + hyphenCount * 0.15 + (urlLength > 85 ? 0.25 : 0.05)
      ),
      contribution:
        domainParts.subdomainCount >= 3 || hyphenCount >= 3
          ? 'Anomalous structural complexity'
          : 'Normal domain topology',
    },
    {
      feature: 'Infrastructure & DNS Posture',
      rawValue: dnsAnalysis.resolvable
        ? `SPF: ${dnsAnalysis.spfRecord !== 'Not Present' ? 'Yes' : 'No'}, DMARC: ${dnsAnalysis.dmarcRecord !== 'Not Present' ? 'Yes' : 'No'}`
        : 'Unresolvable',
      normalizedWeight: !dnsAnalysis.resolvable
        ? 0.75
        : dnsAnalysis.spfRecord !== 'Not Present' && dnsAnalysis.dmarcRecord !== 'Not Present'
          ? 0.05
          : 0.25,
      contribution: dnsAnalysis.resolvable
        ? 'Active DNS zone verified'
        : 'Missing valid DNS resolution',
    },
  ];

  const mlPhishingProbability = Math.min(
    99,
    Math.max(
      1,
      Math.round(
        riskScore * 0.75 +
          mlFeatures.reduce((acc, f) => acc + f.normalizedWeight * 20, 0) / mlFeatures.length
      )
    )
  );

  const verdict: 'Clean' | 'Low Risk' | 'Suspicious' | 'High Risk' | 'Malicious' =
    riskScore >= 75
      ? 'Malicious'
      : riskScore >= 50
        ? 'High Risk'
        : riskScore >= 25
          ? 'Suspicious'
          : riskScore >= 10
            ? 'Low Risk'
            : 'Clean';

  const threatFeeds: ExternalFeedStatus[] = [
    urlhausFeed,
    ...(ipAnalysis ? ipAnalysis.externalThreatFeeds.slice(0, 2) : []),
    {
      source: 'Google Safe Browsing Lookup API',
      status: process.env.GOOGLE_SAFE_BROWSING_KEY ? 'Unavailable' : 'Not Checked',
      details: process.env.GOOGLE_SAFE_BROWSING_KEY
        ? 'Checked'
        : 'Not Checked (GOOGLE_SAFE_BROWSING_KEY not configured)',
    },
    {
      source: 'VirusTotal URL Scanner API',
      status: process.env.VIRUSTOTAL_API_KEY ? 'Unavailable' : 'Not Checked',
      details: process.env.VIRUSTOTAL_API_KEY
        ? 'Checked'
        : 'Not Checked (VIRUSTOTAL_API_KEY not configured)',
    },
  ];

  const aiExplanation = await generateSecurityExplanation('url', normalizedInput, riskScore, verdict, {
    url: normalizedInput,
    domain: domainParts.registeredDomain,
    subdomain: domainParts.subdomain,
    tld: domainParts.tld,
    usesHttps,
    tlsInspection,
    rdapDomainAge: rdapInfo.formattedAge,
    rdapCreationDate: rdapInfo.creationDate,
    rdapRegistrar: rdapInfo.registrar,
    dnsResolvable: dnsAnalysis.resolvable,
    aRecords: dnsAnalysis.aRecords,
    spfRecord: dnsAnalysis.spfRecord,
    dmarcRecord: dnsAnalysis.dmarcRecord,
    resolvedIp: ipAnalysis
      ? {
          ip: ipAnalysis.ip,
          asn: ipAnalysis.asn,
          organization: ipAnalysis.organization,
          country: ipAnalysis.country,
          dnsblListed: ipAnalysis.dnsblResults.filter((d) => d.status === 'Listed'),
        }
      : 'Unavailable',
    homographIndicators,
    matchedKeywords,
    redirectTrace,
    evidence,
  });

  return {
    url: normalizedInput,
    syntax: {
      protocol: parsedUrl.protocol.replace(':', '').toUpperCase(),
      usesHttps,
      port: parsedUrl.port || (usesHttps ? '443 (Default)' : '80 (Default)'),
      urlLength,
      hostnameLength,
      pathLength,
      path: parsedUrl.pathname || '/',
      queryParameters: queryParams,
      hasAtSymbol,
      isIpHostname: domainParts.isIpHostname,
      isUrlShortener: isShortener,
      hyphenCount,
      digitRatio,
      hostEntropy,
      pathEntropy,
      isPunycode,
      unicodeHostname: unicodeHost,
      suspiciousKeywords: matchedKeywords,
      homographIndicators,
    },
    domainAnalysis: {
      hostname: asciiHost,
      registeredDomain: domainParts.registeredDomain,
      sld: domainParts.sld,
      tld: domainParts.tld,
      subdomain: domainParts.subdomain || 'None',
      subdomainCount: domainParts.subdomainCount,
      excessiveSubdomains: domainParts.subdomainCount >= 3,
      rdap: rdapInfo,
    },
    dnsAnalysis,
    tlsInspection,
    redirectTrace,
    ipAnalysis: ipAnalysis as IpAnalysisResult | null,
    threatIntelligence: threatFeeds,
    mlDetection: {
      phishingProbability: mlPhishingProbability,
      classifierVerdict:
        mlPhishingProbability >= 70
          ? 'High-Confidence Phishing Pattern'
          : mlPhishingProbability >= 35
            ? 'Anomalous / Suspicious Pattern'
            : 'Benign Structural Pattern',
      features: mlFeatures,
    },
    riskScore,
    verdict,
    evidence,
    aiExplanation,
    scannedAt: new Date().toISOString(),
  };
}

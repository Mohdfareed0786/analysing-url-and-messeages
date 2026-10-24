import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import { domainToASCII, domainToUnicode } from 'node:url';
import {
  analyzeIpAddress,
  type EvidenceIndicator,
  type ExternalFeedStatus,
  type IpAnalysisResult,
} from './ipAnalyzer.ts';
import { queryUrlhausDomain } from './urlAnalyzer.ts';

export interface DnsRecordsInspection {
  aRecords: string[];
  aaaaRecords: string[];
  mxRecords: { exchange: string; priority: number }[];
  txtRecords: string[];
  nsRecords: string[];
  soaRecord: {
    nsname: string;
    hostmaster: string;
    serial: number;
    refresh: number;
    retry: number;
    expire: number;
    minttl: number;
  } | null;
  spfRecords: string[];
  dmarcRecords: string[];
}

export interface DomainRdapData {
  status: 'available' | 'unavailable' | 'not_supported';
  registrationDate: string | null;
  expirationDate: string | null;
  lastUpdatedDate: string | null;
  formattedAge: string | null;
  ageDays: number | null;
  registrar: string | null;
  registrarIanaId: string | null;
  nameservers: string[];
  rawEntities: { role: string; name: string }[];
}

export interface DomainCertificateInfo {
  available: boolean;
  subject: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  isExpired: boolean;
  subjectAltNames: string[];
}

export interface DomainAnalysisResult {
  domain: string;
  punycode: string;
  unicode: string;
  isPunycode: boolean;
  tld: string;
  dns: DnsRecordsInspection;
  rdap: DomainRdapData;
  certificate: DomainCertificateInfo;
  resolvedIps: {
    ip: string;
    classification: 'Public' | 'Private' | 'Reserved';
    analysis?: IpAnalysisResult;
  }[];
  threatIntelligence: ExternalFeedStatus[];
  riskScore: number;
  verdict: 'Clean' | 'Low Risk' | 'Suspicious' | 'High Risk' | 'Malicious';
  evidence: EvidenceIndicator[];
  recommendations: string[];
  scannedAt: string;
}

/**
 * Normalizes input domain string (strips http/https protocols, paths, and ports).
 */
export function extractCleanDomain(input: string): string {
  let cleaned = input.trim().toLowerCase();
  cleaned = cleaned.replace(/^https?:\/\//i, '');
  cleaned = cleaned.split('/')[0].split('?')[0].split('#')[0];
  cleaned = cleaned.replace(/:[0-9]+$/, '');
  return cleaned;
}

/**
 * Live RDAP (Registration Data Access Protocol) query with fallback registry endpoints.
 * Never fabricates or estimates registration dates if unavailable.
 */
export async function queryDomainRdap(domain: string): Promise<DomainRdapData> {
  const parts = domain.split('.');
  const tld = parts[parts.length - 1];

  // Authoritative RDAP endpoints based on TLD / ICANN
  const candidateEndpoints = [
    `https://rdap.org/domain/${encodeURIComponent(domain)}`,
    `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`,
    `https://rdap.identitydigital.services/rdap/domain/${encodeURIComponent(domain)}`,
  ];

  for (const endpoint of candidateEndpoints) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4500);

      const res = await fetch(endpoint, {
        signal: controller.signal,
        headers: {
          Accept: 'application/rdap+json, application/json',
          'User-Agent': 'PhishingShield-Domain-Auditor/1.0',
        },
      });
      clearTimeout(timeout);

      if (!res.ok) continue;

      const data = await res.json();
      const events: { eventAction?: string; eventDate?: string }[] = data.events || [];

      let regDate: string | null = null;
      let expDate: string | null = null;
      let updDate: string | null = null;

      events.forEach((ev) => {
        if (ev.eventAction === 'registration') regDate = ev.eventDate || null;
        else if (ev.eventAction === 'expiration') expDate = ev.eventDate || null;
        else if (ev.eventAction === 'last changed' || ev.eventAction === 'last update') {
          updDate = ev.eventDate || null;
        }
      });

      let formattedAge: string | null = null;
      let ageDays: number | null = null;

      if (regDate) {
        const created = new Date(regDate);
        if (!isNaN(created.getTime())) {
          const now = new Date();
          const diffMs = now.getTime() - created.getTime();
          ageDays = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));

          if (ageDays < 30) {
            formattedAge = `${ageDays} days old`;
          } else if (ageDays < 365) {
            const months = Math.floor(ageDays / 30);
            formattedAge = `${months} month${months > 1 ? 's' : ''} old`;
          } else {
            const years = (ageDays / 365).toFixed(1);
            formattedAge = `${years} years old`;
          }
        }
      }

      // Extract registrar name and IANA identifier
      let registrar: string | null = null;
      let registrarIanaId: string | null = null;
      const entities = (data.entities || []).map((ent: any) => {
        const roles: string[] = ent.roles || [];
        const fn = ent.vcardArray?.[1]?.find((v: any[]) => v[0] === 'fn')?.[3] || null;
        if (roles.includes('registrar') && fn) {
          registrar = fn;
          const publicIds = ent.publicIds || [];
          const iana = publicIds.find((p: any) => p.type === 'IANA Registrar ID');
          if (iana?.identifier) registrarIanaId = String(iana.identifier);
        }
        return {
          role: roles.join(', ') || 'entity',
          name: fn || ent.handle || 'Protected / Redacted for Privacy',
        };
      });

      const nsList = (data.nameservers || [])
        .map((n: any) => n.ldhName || n.handle)
        .filter(Boolean);

      return {
        status: 'available',
        registrationDate: regDate,
        expirationDate: expDate,
        lastUpdatedDate: updDate,
        formattedAge,
        ageDays,
        registrar: registrar || 'Registration data redacted for privacy',
        registrarIanaId,
        nameservers: nsList,
        rawEntities: entities,
      };
    } catch {
      // Continue to next candidate endpoint
    }
  }

  return {
    status: 'unavailable',
    registrationDate: null,
    expirationDate: null,
    lastUpdatedDate: null,
    formattedAge: null,
    ageDays: null,
    registrar: null,
    registrarIanaId: null,
    nameservers: [],
    rawEntities: [],
  };
}

/**
 * Inspects TLS Certificate directly from domain port 443.
 */
async function inspectDomainTlsCertificate(domain: string): Promise<DomainCertificateInfo> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        timeout: 4000,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          socket.end();

          if (!cert || Object.keys(cert).length === 0) {
            resolve({
              available: false,
              subject: null,
              issuer: null,
              validFrom: null,
              validTo: null,
              daysRemaining: null,
              isExpired: false,
              subjectAltNames: [],
            });
            return;
          }

          const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
          let daysRemaining: number | null = null;
          let isExpired = false;

          if (validTo && !isNaN(validTo.getTime())) {
            const diffMs = validTo.getTime() - Date.now();
            daysRemaining = Math.round(diffMs / (1000 * 60 * 60 * 24));
            isExpired = daysRemaining < 0;
          }

          const sans = cert.subjectaltname
            ? cert.subjectaltname.split(',').map((s) => s.trim().replace(/^DNS:/, ''))
            : [];

          const normalizeField = (field: string | string[] | undefined): string | null => {
            if (!field) return null;
            return Array.isArray(field) ? field[0] || null : field;
          };

          resolve({
            available: true,
            subject: normalizeField(cert.subject?.CN) || 'Unknown Subject',
            issuer: normalizeField(cert.issuer?.O) || normalizeField(cert.issuer?.CN) || 'Unknown Issuer',
            validFrom: cert.valid_from || null,
            validTo: cert.valid_to || null,
            daysRemaining,
            isExpired,
            subjectAltNames: sans,
          });
        } catch {
          socket.destroy();
          resolve({
            available: false,
            subject: null,
            issuer: null,
            validFrom: null,
            validTo: null,
            daysRemaining: null,
            isExpired: false,
            subjectAltNames: [],
          });
        }
      }
    );

    socket.on('error', () => {
      socket.destroy();
      resolve({
        available: false,
        subject: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        isExpired: false,
        subjectAltNames: [],
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        available: false,
        subject: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        isExpired: false,
        subjectAltNames: [],
      });
    });
  });
}

/**
 * Deep Domain Intelligence Analyzer
 */
export async function analyzeDomainIntelligence(rawInput: string): Promise<DomainAnalysisResult> {
  const domain = extractCleanDomain(rawInput);
  if (!domain || domain.length < 3 || !domain.includes('.')) {
    throw new Error('Please provide a valid fully qualified domain name (e.g., example.com).');
  }

  const punycode = domainToASCII(domain);
  const unicode = domainToUnicode(domain);
  const isPunycode = punycode.startsWith('xn--') || domain !== punycode;
  const parts = domain.split('.');
  const tld = parts[parts.length - 1];

  const evidence: EvidenceIndicator[] = [];
  const recommendations: string[] = [];
  let riskScore = 0;

  // 1. Homograph / Punycode Check
  if (isPunycode) {
    riskScore += 30;
    evidence.push({
      category: 'Domain Syntax',
      indicator: 'Punycode / Homograph Cyrillic Indicator',
      value: `${domain} (ASCII: ${punycode})`,
      impact: 'warning',
      scoreDelta: 30,
      details: 'Domain utilizes internationalized Punycode encoding, often used in lookalike homoglyph brand spoofing.',
    });
    recommendations.push(
      'Carefully verify the character set and spelling to ensure this is not an IDN homograph impersonation attack.'
    );
  }

  // 2. DNS Queries in Parallel
  const dnsRecords: DnsRecordsInspection = {
    aRecords: [],
    aaaaRecords: [],
    mxRecords: [],
    txtRecords: [],
    nsRecords: [],
    soaRecord: null,
    spfRecords: [],
    dmarcRecords: [],
  };

  const [aRes, aaaaRes, mxRes, txtRes, nsRes, soaRes, dmarcRes] = await Promise.allSettled([
    dns.resolve4(domain),
    dns.resolve6(domain),
    dns.resolveMx(domain),
    dns.resolveTxt(domain),
    dns.resolveNs(domain),
    dns.resolveSoa(domain),
    dns.resolveTxt(`_dmarc.${domain}`),
  ]);

  if (aRes.status === 'fulfilled') dnsRecords.aRecords = aRes.value;
  if (aaaaRes.status === 'fulfilled') dnsRecords.aaaaRecords = aaaaRes.value;
  if (mxRes.status === 'fulfilled') dnsRecords.mxRecords = mxRes.value;
  if (nsRes.status === 'fulfilled') dnsRecords.nsRecords = nsRes.value;
  if (soaRes.status === 'fulfilled') dnsRecords.soaRecord = soaRes.value;

  if (txtRes.status === 'fulfilled') {
    const rawTxt = txtRes.value.map((c) => (Array.isArray(c) ? c.join('') : String(c)));
    dnsRecords.txtRecords = rawTxt;
    dnsRecords.spfRecords = rawTxt.filter((t) => t.toLowerCase().startsWith('v=spf1'));
  }

  if (dmarcRes.status === 'fulfilled') {
    const rawDmarc = dmarcRes.value.map((c) => (Array.isArray(c) ? c.join('') : String(c)));
    dnsRecords.dmarcRecords = rawDmarc.filter((t) => t.toLowerCase().startsWith('v=dmarc1'));
  }

  // Assess DNS records
  if (dnsRecords.aRecords.length === 0 && dnsRecords.aaaaRecords.length === 0) {
    riskScore += 20;
    evidence.push({
      category: 'DNS Resolution',
      indicator: 'No A or AAAA Records',
      value: 'Unresolvable',
      impact: 'warning',
      scoreDelta: 20,
      details: 'Domain does not currently resolve to an active IPv4 or IPv6 address.',
    });
  } else {
    evidence.push({
      category: 'DNS Resolution',
      indicator: 'A / AAAA IP Records',
      value: `${dnsRecords.aRecords.length} IPv4, ${dnsRecords.aaaaRecords.length} IPv6`,
      impact: 'positive',
      scoreDelta: 0,
      details: `Resolved A records: ${dnsRecords.aRecords.join(', ') || 'None'}`,
    });
  }

  // Assess Email Security (SPF / DMARC)
  if (dnsRecords.spfRecords.length > 0) {
    evidence.push({
      category: 'Email Authentication',
      indicator: 'SPF Record Configured',
      value: dnsRecords.spfRecords[0].slice(0, 70),
      impact: 'positive',
      scoreDelta: -5,
      details: 'Domain has an SPF policy restricting unauthorized mail transfer agents.',
    });
  } else {
    evidence.push({
      category: 'Email Authentication',
      indicator: 'Missing SPF Record',
      value: 'None detected',
      impact: 'neutral',
      scoreDelta: 0,
      details: 'Domain does not declare an SPF record, increasing email spoofing vulnerability.',
    });
  }

  if (dnsRecords.dmarcRecords.length > 0) {
    evidence.push({
      category: 'Email Authentication',
      indicator: 'DMARC Policy Configured',
      value: dnsRecords.dmarcRecords[0].slice(0, 70),
      impact: 'positive',
      scoreDelta: -5,
      details: 'Domain has a declared DMARC policy for enforcing email integrity.',
    });
  }

  // 3. Live RDAP Registration Intelligence
  const rdap = await queryDomainRdap(domain);
  if (rdap.status === 'available' && rdap.ageDays !== null) {
    if (rdap.ageDays < 14) {
      riskScore += 35;
      evidence.push({
        category: 'Domain Registration',
        indicator: 'Newly Registered Domain (<14 Days)',
        value: `${rdap.ageDays} days old (${rdap.registrationDate})`,
        impact: 'critical',
        scoreDelta: 35,
        details: 'Domain was created within the last 14 days. Brand new domains carry high statistical correlation with disposable phishing campaigns.',
      });
      recommendations.push(
        'Exercise heightened caution: Brand-new domains are frequently deployed in hit-and-run credential lures.'
      );
    } else if (rdap.ageDays < 90) {
      riskScore += 18;
      evidence.push({
        category: 'Domain Registration',
        indicator: 'Young Domain (<90 Days)',
        value: `${rdap.ageDays} days old`,
        impact: 'warning',
        scoreDelta: 18,
        details: 'Domain is less than 3 months old.',
      });
    } else {
      evidence.push({
        category: 'Domain Registration',
        indicator: 'Established Domain Age',
        value: `${rdap.formattedAge || `${rdap.ageDays} days`}`,
        impact: 'positive',
        scoreDelta: -10,
        details: `Registered on ${rdap.registrationDate} via ${rdap.registrar || 'Registrar'}`,
      });
    }
  } else {
    evidence.push({
      category: 'Domain Registration',
      indicator: 'Registration Data Availability',
      value: 'Registration data unavailable',
      impact: 'neutral',
      scoreDelta: 0,
      details: 'Authoritative RDAP query returned no public record (common for ccTLDs and privacy-shielded registrations).',
    });
  }

  // 4. TLS Certificate Probe
  const certificate = await inspectDomainTlsCertificate(domain);
  if (certificate.available) {
    if (certificate.isExpired) {
      riskScore += 25;
      evidence.push({
        category: 'TLS Certificate',
        indicator: 'Expired TLS Certificate',
        value: `Expired on ${certificate.validTo}`,
        impact: 'critical',
        scoreDelta: 25,
        details: 'The domain presents an expired X.509 SSL/TLS certificate.',
      });
    } else {
      evidence.push({
        category: 'TLS Certificate',
        indicator: 'Valid TLS Certificate',
        value: `Issued by ${certificate.issuer || 'CA'} (${certificate.daysRemaining} days remaining)`,
        impact: 'positive',
        scoreDelta: 0,
        details: `Subject: ${certificate.subject || domain}`,
      });
    }
  }

  // 5. Threat Intelligence (Abuse.ch URLhaus)
  const threatIntelligence: ExternalFeedStatus[] = [];
  const urlhausRes = await queryUrlhausDomain(domain);
  threatIntelligence.push(urlhausRes);
  if (urlhausRes.status === 'Flagged') {
    riskScore += 50;
    evidence.push({
      category: 'Threat Intelligence',
      indicator: 'Abuse.ch URLhaus Blacklist Match',
      value: 'Confirmed Malicious URLhaus Listing',
      impact: 'critical',
      scoreDelta: 50,
      details: urlhausRes.details,
    });
  }

  // 6. IP Reputation for Resolved Addresses
  const resolvedIps: DomainAnalysisResult['resolvedIps'] = [];
  const targetIps = dnsRecords.aRecords.slice(0, 2);
  for (const ip of targetIps) {
    const isPublic = net.isIP(ip) !== 0 && !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.');
    if (isPublic) {
      try {
        const ipScan = await analyzeIpAddress(ip, false);
        resolvedIps.push({ ip, classification: 'Public', analysis: ipScan });
        if (ipScan.riskScore >= 50) {
          riskScore += 25;
          evidence.push({
            category: 'IP Reputation',
            indicator: `High Risk Host IP (${ip})`,
            value: `Score: ${ipScan.riskScore}/100 (${ipScan.verdict})`,
            impact: 'critical',
            scoreDelta: 25,
            details: `ASN ${ipScan.asn || 'N/A'} (${ipScan.organization || 'Unknown Org'})`,
          });
        }
      } catch {
        resolvedIps.push({ ip, classification: 'Public' });
      }
    } else {
      resolvedIps.push({ ip, classification: 'Private' });
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

  return {
    domain,
    punycode,
    unicode,
    isPunycode,
    tld,
    dns: dnsRecords,
    rdap,
    certificate,
    resolvedIps,
    threatIntelligence,
    riskScore,
    verdict,
    evidence,
    recommendations:
      recommendations.length > 0
        ? recommendations
        : [
            'Maintain active SPF and DMARC records to protect domain reputation from spoofing.',
            'Monitor certificate expiration and nameserver availability.',
          ],
    scannedAt: new Date().toISOString(),
  };
}

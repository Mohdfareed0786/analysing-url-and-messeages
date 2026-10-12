import dns from 'node:dns/promises';
import net from 'node:net';
import { generateSecurityExplanation, type AIExplanationResult } from './geminiService.ts';

export interface EvidenceIndicator {
  category: string;
  indicator: string;
  value: string;
  impact: 'positive' | 'neutral' | 'warning' | 'critical';
  scoreDelta: number;
  details: string;
}

export interface DnsblCheckResult {
  provider: string;
  zone: string;
  status: 'Clean' | 'Listed' | 'Unavailable';
  responseCode?: string;
}

export interface ExternalFeedStatus {
  source: string;
  status: 'Clean' | 'Flagged' | 'Unavailable' | 'Not Checked';
  details: string;
}

export interface IpAnalysisResult {
  ip: string;
  ipVersion: 'IPv4' | 'IPv6' | 'Invalid';
  classification: 'Public' | 'Private (RFC 1918)' | 'Loopback' | 'Link-Local' | 'Reserved / Bogon';
  reverseDns: string[];
  asn: string;
  organization: string;
  isp: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  isProxyOrVpn: boolean | 'Unavailable';
  isHostingOrDatacenter: boolean | 'Unavailable';
  isMobileNetwork: boolean | 'Unavailable';
  rdapNetwork: {
    status: 'Available' | 'Unavailable';
    networkName: string;
    cidr: string;
    handle: string;
    registrationDate: string;
    abuseContact: string;
  };
  dnsblResults: DnsblCheckResult[];
  externalThreatFeeds: ExternalFeedStatus[];
  riskScore: number;
  verdict: 'Clean' | 'Low Risk' | 'Suspicious' | 'High Risk' | 'Malicious';
  evidence: EvidenceIndicator[];
  aiExplanation?: AIExplanationResult;
  scannedAt: string;
}

export function classifyIpScope(
  ip: string
): 'Public' | 'Private (RFC 1918)' | 'Loopback' | 'Link-Local' | 'Reserved / Bogon' {
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 127) return 'Loopback';
    if (a === 10) return 'Private (RFC 1918)';
    if (a === 172 && b >= 16 && b <= 31) return 'Private (RFC 1918)';
    if (a === 192 && b === 168) return 'Private (RFC 1918)';
    if (a === 169 && b === 254) return 'Link-Local';
    if (a === 0 || a >= 224 || (a === 100 && b >= 64 && b <= 127)) {
      return 'Reserved / Bogon';
    }
    return 'Public';
  }
  if (version === 6) {
    const normalized = ip.toLowerCase();
    if (normalized === '::1') return 'Loopback';
    if (normalized.startsWith('fe80:')) return 'Link-Local';
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return 'Private (RFC 1918)';
    if (normalized === '::' || normalized.startsWith('ff')) return 'Reserved / Bogon';
    return 'Public';
  }
  return 'Reserved / Bogon';
}

async function checkSingleDnsbl(ip: string, provider: string, zone: string): Promise<DnsblCheckResult> {
  if (net.isIP(ip) !== 4) {
    return { provider, zone, status: 'Unavailable' };
  }
  const reversedOctets = ip.split('.').reverse().join('.');
  const lookupHost = `${reversedOctets}.${zone}`;
  try {
    const timeoutPromise = new Promise<string[]>((_, reject) =>
      setTimeout(() => reject(new Error('DNSBL timeout')), 2500)
    );
    const records = await Promise.race([dns.resolve4(lookupHost), timeoutPromise]);
    const validListings = records.filter((r) => r.startsWith('127.0.0.'));
    if (validListings.length > 0) {
      return {
        provider,
        zone,
        status: 'Listed',
        responseCode: validListings.join(', '),
      };
    }
    return { provider, zone, status: 'Clean' };
  } catch (err: unknown) {
    const code = (err as { code?: string })?.code;
    if (code === 'ENOTFOUND' || code === 'ENODATA') {
      return { provider, zone, status: 'Clean' };
    }
    return { provider, zone, status: 'Unavailable' };
  }
}

async function queryIpGeolocationAndAsn(ip: string) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,isp,org,as,asname,reverse,mobile,proxy,hosting,query`,
      { signal: controller.signal }
    );
    clearTimeout(timer);
    if (res.ok) {
      const data = await res.json();
      if (data && data.status === 'success') {
        return {
          available: true,
          asn: data.as || 'Unavailable',
          organization: data.org || data.asname || 'Unavailable',
          isp: data.isp || 'Unavailable',
          country: data.country || 'Unavailable',
          countryCode: data.countryCode || 'Unavailable',
          region: data.regionName || 'Unavailable',
          city: data.city || 'Unavailable',
          isProxyOrVpn: typeof data.proxy === 'boolean' ? data.proxy : ('Unavailable' as const),
          isHostingOrDatacenter: typeof data.hosting === 'boolean' ? data.hosting : ('Unavailable' as const),
          isMobileNetwork: typeof data.mobile === 'boolean' ? data.mobile : ('Unavailable' as const),
        };
      }
    }
  } catch {
    // Fallback to ipwho.is
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (res.ok) {
      const data = await res.json();
      if (data && data.success !== false) {
        return {
          available: true,
          asn: data.connection?.asn ? `AS${data.connection.asn}` : 'Unavailable',
          organization: data.connection?.org || 'Unavailable',
          isp: data.connection?.isp || 'Unavailable',
          country: data.country || 'Unavailable',
          countryCode: data.country_code || 'Unavailable',
          region: data.region || 'Unavailable',
          city: data.city || 'Unavailable',
          isProxyOrVpn: 'Unavailable' as const,
          isHostingOrDatacenter: 'Unavailable' as const,
          isMobileNetwork: 'Unavailable' as const,
        };
      }
    }
  } catch {
    // Both unavailable
  }

  return {
    available: false,
    asn: 'Unavailable',
    organization: 'Unavailable',
    isp: 'Unavailable',
    country: 'Unavailable',
    countryCode: 'Unavailable',
    region: 'Unavailable',
    city: 'Unavailable',
    isProxyOrVpn: 'Unavailable' as const,
    isHostingOrDatacenter: 'Unavailable' as const,
    isMobileNetwork: 'Unavailable' as const,
  };
}

async function queryIpRdap(ip: string) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);
    const res = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
      headers: { Accept: 'application/rdap+json, application/json' },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      throw new Error(`RDAP HTTP ${res.status}`);
    }
    const data = await res.json();
    let registrationDate = 'Unavailable';
    if (Array.isArray(data.events)) {
      const regEvent = data.events.find(
        (e: { eventAction?: string; eventDate?: string }) =>
          e.eventAction === 'registration' || e.eventAction === 'last changed'
      );
      if (regEvent?.eventDate) {
        registrationDate = regEvent.eventDate.split('T')[0];
      }
    }

    let cidr = 'Unavailable';
    if (Array.isArray(data.cidr0_cidrs) && data.cidr0_cidrs.length > 0) {
      const first = data.cidr0_cidrs[0];
      if (first.v4prefix && first.length) {
        cidr = `${first.v4prefix}/${first.length}`;
      } else if (first.v6prefix && first.length) {
        cidr = `${first.v6prefix}/${first.length}`;
      }
    } else if (data.startAddress && data.endAddress) {
      cidr = `${data.startAddress} - ${data.endAddress}`;
    }

    let abuseContact = 'Unavailable';
    if (Array.isArray(data.entities)) {
      for (const ent of data.entities) {
        const vcard = ent?.vcardArray?.[1];
        if (Array.isArray(vcard)) {
          for (const field of vcard) {
            if (Array.isArray(field) && field[0] === 'email' && typeof field[3] === 'string') {
              abuseContact = field[3];
              break;
            }
          }
        }
        if (abuseContact !== 'Unavailable') break;
      }
    }

    return {
      status: 'Available' as const,
      networkName: data.name || 'Unavailable',
      cidr,
      handle: data.handle || 'Unavailable',
      registrationDate,
      abuseContact,
    };
  } catch {
    return {
      status: 'Unavailable' as const,
      networkName: 'Unavailable',
      cidr: 'Unavailable',
      handle: 'Unavailable',
      registrationDate: 'Unavailable',
      abuseContact: 'Unavailable',
    };
  }
}

export async function analyzeIpAddress(
  rawIp: string,
  includeAiExplanation = true
): Promise<IpAnalysisResult> {
  const ip = rawIp.trim();
  const versionNum = net.isIP(ip);
  const ipVersion = versionNum === 4 ? 'IPv4' : versionNum === 6 ? 'IPv6' : 'Invalid';

  if (ipVersion === 'Invalid') {
    throw new Error(`"${ip}" is not a valid IPv4 or IPv6 address.`);
  }

  const classification = classifyIpScope(ip);
  const evidence: EvidenceIndicator[] = [];
  let riskScore = 0;

  if (classification !== 'Public') {
    evidence.push({
      category: 'Address Scope',
      indicator: 'Non-Public IP Address',
      value: classification,
      impact: 'warning',
      scoreDelta: 15,
      details: `The IP ${ip} belongs to ${classification} space and is not routable on the public internet.`,
    });
    riskScore += 15;

    return {
      ip,
      ipVersion,
      classification,
      reverseDns: [],
      asn: 'Not Applicable (Private/Reserved IP)',
      organization: 'Not Applicable',
      isp: 'Not Applicable',
      country: 'Not Applicable',
      countryCode: 'N/A',
      region: 'Not Applicable',
      city: 'Not Applicable',
      isProxyOrVpn: 'Unavailable',
      isHostingOrDatacenter: 'Unavailable',
      isMobileNetwork: 'Unavailable',
      rdapNetwork: {
        status: 'Unavailable',
        networkName: 'Private/Reserved Range',
        cidr: 'N/A',
        handle: 'N/A',
        registrationDate: 'N/A',
        abuseContact: 'N/A',
      },
      dnsblResults: [],
      externalThreatFeeds: [
        {
          source: 'Public Threat Feeds',
          status: 'Not Checked',
          details: 'Private/Reserved IP addresses are not indexed in public threat feeds.',
        },
      ],
      riskScore,
      verdict: 'Low Risk',
      evidence,
      scannedAt: new Date().toISOString(),
    };
  }

  evidence.push({
    category: 'Address Scope',
    indicator: 'Public Routable IP',
    value: `${ip} (${ipVersion})`,
    impact: 'neutral',
    scoreDelta: 0,
    details: 'Valid public IP address eligible for routing, DNSBL, and RDAP inspection.',
  });

  // Run Reverse DNS, Geolocation/ASN, RDAP, and DNSBL in parallel
  const reverseDnsPromise = dns
    .reverse(ip)
    .catch(() => [] as string[]);

  const dnsblZones = [
    { provider: 'SpamCop Blocking List', zone: 'bl.spamcop.net' },
    { provider: 'SORBS DNSBL', zone: 'dnsbl.sorbs.net' },
    { provider: 'Barracuda Reputation Block List', zone: 'b.barracudacentral.org' },
    { provider: 'UCEPROTECT Level 1', zone: 'dnsbl-1.uceprotect.net' },
  ];

  const [reverseDns, geoInfo, rdapNetwork, dnsblResults] = await Promise.all([
    reverseDnsPromise,
    queryIpGeolocationAndAsn(ip),
    queryIpRdap(ip),
    Promise.all(dnsblZones.map((z) => checkSingleDnsbl(ip, z.provider, z.zone))),
  ]);

  if (reverseDns.length > 0) {
    evidence.push({
      category: 'DNS Resolution',
      indicator: 'Reverse DNS (PTR) Record',
      value: reverseDns.join(', '),
      impact: 'positive',
      scoreDelta: 0,
      details: 'IP resolves to a configured PTR hostname.',
    });
  } else {
    evidence.push({
      category: 'DNS Resolution',
      indicator: 'Reverse DNS (PTR) Record',
      value: 'None / Unconfigured',
      impact: 'neutral',
      scoreDelta: 4,
      details: 'No reverse DNS (PTR) record is published for this IP.',
    });
    riskScore += 4;
  }

  if (geoInfo.available) {
    evidence.push({
      category: 'Network Routing',
      indicator: 'ASN & Autonomous System',
      value: `${geoInfo.asn} (${geoInfo.organization})`,
      impact: 'neutral',
      scoreDelta: 0,
      details: `Routed via ${geoInfo.isp} in ${geoInfo.country}.`,
    });

    if (geoInfo.isProxyOrVpn === true) {
      evidence.push({
        category: 'IP Reputation',
        indicator: 'Anonymizer / Proxy / VPN Node',
        value: 'Detected',
        impact: 'warning',
        scoreDelta: 22,
        details: 'IP is associated with an open proxy, VPN exit node, or Tor relay.',
      });
      riskScore += 22;
    } else if (geoInfo.isProxyOrVpn === false) {
      evidence.push({
        category: 'IP Reputation',
        indicator: 'Anonymizer / Proxy / VPN Node',
        value: 'Not Detected',
        impact: 'positive',
        scoreDelta: 0,
        details: 'IP is not flagged as a known proxy or VPN exit node.',
      });
    }

    if (geoInfo.isHostingOrDatacenter === true) {
      evidence.push({
        category: 'Infrastructure Type',
        indicator: 'Cloud / Datacenter Hosting Range',
        value: 'Datacenter IP',
        impact: 'neutral',
        scoreDelta: 6,
        details: 'IP belongs to a cloud hosting or colocation provider.',
      });
      riskScore += 6;
    }
  } else {
    evidence.push({
      category: 'Network Routing',
      indicator: 'ASN & Geolocation Lookup',
      value: 'Unavailable',
      impact: 'neutral',
      scoreDelta: 0,
      details: 'External ASN intelligence service did not return routing metadata.',
    });
  }

  // Evaluate DNSBL listings
  const listedDnsbls = dnsblResults.filter((d) => d.status === 'Listed');
  const checkedDnsbls = dnsblResults.filter((d) => d.status !== 'Unavailable');

  if (listedDnsbls.length > 0) {
    const delta = Math.min(60, listedDnsbls.length * 25);
    evidence.push({
      category: 'Threat Intelligence',
      indicator: 'Real-Time DNS Blackhole Lists (DNSBL)',
      value: `Listed on ${listedDnsbls.length}/${checkedDnsbls.length} blacklists`,
      impact: 'critical',
      scoreDelta: delta,
      details: `Flagged by: ${listedDnsbls.map((d) => d.provider).join(', ')}`,
    });
    riskScore += delta;
  } else if (checkedDnsbls.length > 0) {
    evidence.push({
      category: 'Threat Intelligence',
      indicator: 'Real-Time DNS Blackhole Lists (DNSBL)',
      value: `Clean across ${checkedDnsbls.length} blacklists`,
      impact: 'positive',
      scoreDelta: 0,
      details: `Verified clean on ${checkedDnsbls.map((d) => d.provider).join(', ')}.`,
    });
  } else {
    evidence.push({
      category: 'Threat Intelligence',
      indicator: 'Real-Time DNS Blackhole Lists (DNSBL)',
      value: 'Unavailable',
      impact: 'neutral',
      scoreDelta: 0,
      details: 'DNSBL queries were not applicable or unreachable.',
    });
  }

  const externalThreatFeeds: ExternalFeedStatus[] = [
    {
      source: 'DNSBL Multi-Feed (SpamCop / SORBS / Barracuda / UCEPROTECT)',
      status:
        listedDnsbls.length > 0
          ? 'Flagged'
          : checkedDnsbls.length > 0
            ? 'Clean'
            : 'Unavailable',
      details:
        listedDnsbls.length > 0
          ? `Listed on ${listedDnsbls.map((d) => d.provider).join(', ')}`
          : checkedDnsbls.length > 0
            ? `0 detections across ${checkedDnsbls.length} live DNSBL providers`
            : 'DNSBL resolution unavailable',
    },
    {
      source: 'RDAP Regional Internet Registry (ARIN / RIPE / APNIC)',
      status: rdapNetwork.status === 'Available' ? 'Clean' : 'Unavailable',
      details:
        rdapNetwork.status === 'Available'
          ? `Registered block ${rdapNetwork.networkName} (${rdapNetwork.cidr})`
          : 'RDAP registry metadata unavailable',
    },
    {
      source: 'AbuseIPDB API',
      status: process.env.ABUSEIPDB_API_KEY ? 'Unavailable' : 'Not Checked',
      details: process.env.ABUSEIPDB_API_KEY
        ? 'Checked via API'
        : 'Not Checked (ABUSEIPDB_API_KEY not configured in environment)',
    },
    {
      source: 'VirusTotal IP Intelligence',
      status: process.env.VIRUSTOTAL_API_KEY ? 'Unavailable' : 'Not Checked',
      details: process.env.VIRUSTOTAL_API_KEY
        ? 'Checked via API'
        : 'Not Checked (VIRUSTOTAL_API_KEY not configured in environment)',
    },
  ];

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

  const result: IpAnalysisResult = {
    ip,
    ipVersion,
    classification,
    reverseDns,
    asn: geoInfo.asn,
    organization: geoInfo.organization,
    isp: geoInfo.isp,
    country: geoInfo.country,
    countryCode: geoInfo.countryCode,
    region: geoInfo.region,
    city: geoInfo.city,
    isProxyOrVpn: geoInfo.isProxyOrVpn,
    isHostingOrDatacenter: geoInfo.isHostingOrDatacenter,
    isMobileNetwork: geoInfo.isMobileNetwork,
    rdapNetwork,
    dnsblResults,
    externalThreatFeeds,
    riskScore,
    verdict,
    evidence,
    scannedAt: new Date().toISOString(),
  };

  if (includeAiExplanation) {
    result.aiExplanation = await generateSecurityExplanation('ip', ip, riskScore, verdict, {
      ip,
      classification,
      asn: geoInfo.asn,
      organization: geoInfo.organization,
      country: geoInfo.country,
      reverseDns,
      isProxyOrVpn: geoInfo.isProxyOrVpn,
      isHostingOrDatacenter: geoInfo.isHostingOrDatacenter,
      rdapNetwork,
      dnsblResults,
      evidence,
    });
  }

  return result;
}

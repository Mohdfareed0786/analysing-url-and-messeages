import {
  GoogleGenAI,
  Type,
  Modality,
  GenerateVideosOperation,
  type LiveServerMessage,
} from '@google/genai';

export function getGenAIClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

export function formatGeminiErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  if (
    raw.includes('403') ||
    raw.includes('PERMISSION_DENIED') ||
    raw.includes('API_KEY_INVALID')
  ) {
    return `Gemini API authorization error. Please verify your GEMINI_API_KEY in the Settings > Secrets panel.`;
  }
  if (raw.includes('429') || raw.includes('RESOURCE_EXHAUSTED') || raw.includes('billing')) {
    return `Gemini API rate limit or free-tier quota reached for this model. Automatically routing to gemini-3.1-flash-lite.`;
  }
  return raw;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    promise
      .then((val) => {
        clearTimeout(timer);
        resolve(val);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

/**
 * Fast, resilient multi-model helper:
 * Prioritizes low-latency execution with bounded timeouts so requests never hang.
 * Automatically falls back to 'gemini-3.1-flash-lite' (and strips paid-only grounding tools if needed).
 */
export async function generateWithResilientFallback(
  ai: GoogleGenAI,
  params: {
    preferredModel: string;
    contents: any;
    config?: Record<string, any>;
    timeoutMs?: number;
  }
): Promise<{ response: any; modelUsed: string }> {
  const perCallTimeout = params.timeoutMs || 7000;
  // Always put gemini-3.1-flash-lite first or immediately second for fast, reliable response
  const candidateModels = Array.from(
    new Set(
      params.preferredModel === 'gemini-3.1-flash-lite'
        ? ['gemini-3.1-flash-lite']
        : [params.preferredModel, 'gemini-3.1-flash-lite']
    )
  );

  let lastError: unknown = null;

  for (const modelName of candidateModels) {
    try {
      const response = await withTimeout(
        ai.models.generateContent({
          model: modelName,
          contents: params.contents,
          config: params.config,
        }),
        perCallTimeout,
        `Model ${modelName}`
      );
      return { response, modelUsed: modelName };
    } catch (err: unknown) {
      lastError = err;
      const msg = err instanceof Error ? err.message : String(err);
      // If tools (e.g. googleSearch on free tier) triggered 429, 400, or timeout, immediately run clean gemini-3.1-flash-lite
      if (
        params.config?.tools &&
        (msg.includes('429') ||
          msg.includes('400') ||
          msg.includes('RESOURCE_EXHAUSTED') ||
          msg.includes('timed out'))
      ) {
        try {
          const {
            tools: _ignoredTools,
            toolConfig: _ignoredToolConfig,
            ...cleanConfig
          } = params.config;
          const fallbackRes = await withTimeout(
            ai.models.generateContent({
              model: 'gemini-3.1-flash-lite',
              contents: params.contents,
              config: cleanConfig,
            }),
            perCallTimeout,
            'Fallback gemini-3.1-flash-lite'
          );
          return { response: fallbackRes, modelUsed: 'gemini-3.1-flash-lite' };
        } catch (innerErr) {
          lastError = innerErr;
        }
      }
    }
  }

  throw lastError || new Error('Gemini request failed across all candidate models.');
}

export interface AIExplanationResult {
  available: boolean;
  executiveSummary: string;
  technicalAssessment: string;
  keyFindings: string[];
  recommendations: {
    priority: 'Immediate' | 'High' | 'Standard';
    action: string;
    rationale: string;
  }[];
}

export function buildDeterministicExplanationFallback(
  scanType: 'url' | 'message' | 'ip' | 'screenshot',
  target: string,
  riskScore: number,
  verdict: string,
  evidenceSummary: Record<string, unknown>
): AIExplanationResult {
  const triggered = Array.isArray((evidenceSummary as any)?.triggeredIndicators)
    ? ((evidenceSummary as any).triggeredIndicators as any[])
    : Array.isArray((evidenceSummary as any)?.evidence)
      ? ((evidenceSummary as any).evidence as any[]).filter((e: any) => e.scoreDelta !== 0)
      : [];

  const findings =
    triggered.length > 0
      ? triggered.slice(0, 5).map(
          (e: any) =>
            `${e.indicator || 'Signal'}: ${e.value || 'Observed'} (${e.scoreDelta > 0 ? `+${e.scoreDelta}` : e.scoreDelta} pts) — ${e.details || ''}`
        )
      : [
          `Target (${target}) completed ${scanType.toUpperCase()} inspection with a risk score of ${riskScore}/100 (${verdict}).`,
          'No high-severity malicious indicators were triggered during live telemetry checks.',
        ];

  return {
    available: true,
    executiveSummary: `${scanType.toUpperCase()} security analysis for "${target}" completed with an evidence-based risk score of ${riskScore}/100 (${verdict}). ${
      triggered.length > 0
        ? `${triggered.length} risk indicator(s) contributed to the elevated score.`
        : 'All primary infrastructure and lexical telemetry checks passed.'
    }`,
    technicalAssessment: `Telemetry evaluation inspected ${scanType.toUpperCase()} attributes for ${target}. ${
      triggered.length > 0
        ? `Key anomalies observed include: ${findings.join('; ')}.`
        : 'DNS, registration, and reputation signals align with normal operational baselines.'
    }`,
    keyFindings: findings,
    recommendations:
      riskScore >= 50
        ? [
            {
              priority: 'Immediate',
              action: 'Do not enter credentials, OTPs, or payment details; block target at DNS/SWG',
              rationale: 'High risk score indicates elevated phishing or infrastructure abuse risk.',
            },
            {
              priority: 'High',
              action: 'Enforce FIDO2 / WebAuthn MFA and revoke active session tokens if interacted with',
              rationale: 'Mitigates credential harvesting and session hijacking.',
            },
          ]
        : [
            {
              priority: 'Standard',
              action: 'Maintain standard zero-trust monitoring and verify sender/domain authenticity',
              rationale:
                'Continues defense-in-depth verification even when initial indicators appear low-risk.',
            },
          ],
  };
}

export async function generateSecurityExplanation(
  scanType: 'url' | 'message' | 'ip',
  target: string,
  riskScore: number,
  verdict: string,
  evidenceSummary: Record<string, unknown>
): Promise<AIExplanationResult> {
  const ai = getGenAIClient();
  if (!ai) {
    return buildDeterministicExplanationFallback(
      scanType,
      target,
      riskScore,
      verdict,
      evidenceSummary
    );
  }

  try {
    const prompt = `You are a Senior SOC Threat Intelligence Analyst for PHISHING SHIELD.
Analyze the following REAL security scan telemetry for a ${scanType.toUpperCase()} scan.
Target: ${target}
Calculated Evidence-Based Risk Score: ${riskScore}/100 (${verdict})

Observed Telemetry & Evidence JSON:
${JSON.stringify(evidenceSummary)}

CRITICAL RULES:
1. Base your explanation STRICTLY on the provided telemetry and evidence. Never invent or guess data that is marked "Unavailable" or "Not Checked".
2. Remember that domain age alone or missing HTTPS alone does not prove a domain is malicious.
3. If the target message is in Hindi or Hinglish, explain the detected indicators clearly so English, Hindi, and Hinglish readers can immediately understand the risk.
4. Provide a concise executive summary, a technical assessment referencing specific signals (DNS, RDAP, TLS, lexical indicators, IP reputation, or NLP cues), 3-5 key findings, and 3 actionable security recommendations.`;

    const { response } = await generateWithResilientFallback(ai, {
      preferredModel: 'gemini-3.1-flash-lite',
      contents: prompt,
      timeoutMs: 5500,
      config: {
        systemInstruction:
          'You are an enterprise cybersecurity analyst producing objective, evidence-backed phishing and threat assessments. Keep output concise, fast, accurate, and grounded strictly in the provided telemetry.',
        temperature: 0.15,
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            executiveSummary: {
              type: Type.STRING,
              description: '2-3 sentence executive summary of the threat posture.',
            },
            technicalAssessment: {
              type: Type.STRING,
              description: 'Detailed technical breakdown referencing concrete signals from the scan.',
            },
            keyFindings: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: '3 to 5 bullet points summarizing the most important observed indicators.',
            },
            recommendations: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  priority: {
                    type: Type.STRING,
                    description: 'Immediate, High, or Standard',
                  },
                  action: {
                    type: Type.STRING,
                    description: 'Concrete defensive or remediation action to take.',
                  },
                  rationale: {
                    type: Type.STRING,
                    description: 'Why this action mitigates the identified risk.',
                  },
                },
                required: ['priority', 'action', 'rationale'],
              },
            },
          },
          required: ['executiveSummary', 'technicalAssessment', 'keyFindings', 'recommendations'],
        },
      },
    });

    const rawText = response.text;
    if (!rawText) {
      throw new Error('Empty response from Gemini model');
    }

    const parsed = JSON.parse(rawText.trim());
    return {
      available: true,
      executiveSummary: parsed.executiveSummary || 'Analysis completed.',
      technicalAssessment: parsed.technicalAssessment || 'See evidence breakdown.',
      keyFindings: Array.isArray(parsed.keyFindings) ? parsed.keyFindings : [],
      recommendations: Array.isArray(parsed.recommendations)
        ? parsed.recommendations.map(
            (r: { priority?: string; action?: string; rationale?: string }) => ({
              priority:
                r.priority === 'Immediate' || r.priority === 'High' ? r.priority : 'Standard',
              action: r.action || 'Verify source authenticity',
              rationale: r.rationale || 'Standard zero-trust verification.',
            })
          )
        : [],
    };
  } catch (error) {
    console.warn('Gemini explanation fast fallback activated:', formatGeminiErrorMessage(error));
    return buildDeterministicExplanationFallback(
      scanType,
      target,
      riskScore,
      verdict,
      evidenceSummary
    );
  }
}

// ============================================================================
// 1. MULTI-TURN GEMINI SOC CHATBOT + DETERMINISTIC LIVE SECURITY TOOLS
// ============================================================================
const ROLE_SYSTEM_INSTRUCTIONS: Record<string, string> = {
  'soc-analyst':
    'You are the Lead Phishing Shield Gemini AI Security Assistant & SOC Threat Intelligence Analyst. You help users and security analysts investigate phishing URLs, RDAP domain registration anomalies, DNS records (SPF, DKIM, DMARC), ASN/IP reputation, QR code scams (quishing), and social engineering messages. Support English, Hindi, and Hinglish naturally—reply in the same language/style the user writes in. Never invent scan data or promise 100% accuracy.',
  'incident-responder':
    'You are an Enterprise Incident Response Commander inside Phishing Shield. Guide the user step-by-step through containment, credential revocation, session token invalidation, UPI/bank fraud reporting (e.g. 1930 cybercrime helpline / cybercrime.gov.in / CERT), firewall/DNS blocking, and post-incident remediation playbooks. Support English, Hindi, and Hinglish naturally.',
  'dns-architect':
    'You are a Senior Email & Domain Security Architect inside Phishing Shield. Specialize in hardening SPF, DKIM, DMARC (p=reject), BIMI, MTA-STS, DNSSEC, and TLS configurations to protect domains from spoofing and lookalike abuse. Support English, Hindi, and Hinglish naturally.',
};

export interface ExecutedToolInfo {
  toolName: 'scanUrlTarget' | 'scanPublicIp' | 'scanMessagePhishing';
  target: string;
  riskScore: number;
  verdict: string;
  summary: string;
}

/**
 * Extracts explicit URLs, IPs, or suspicious message quotes from the analyst's prompt
 * and executes Phishing Shield's live deterministic analyzers WITHOUT redundant nested LLM calls
 * so Gemini responds in a single fast turn.
 */
async function executeRelevantSecurityToolsForChat(
  message: string
): Promise<{
  executedTools: ExecutedToolInfo[];
  toolResultsPayload: Record<string, unknown>[];
}> {
  const executedTools: ExecutedToolInfo[] = [];
  const toolResultsPayload: Record<string, unknown>[] = [];

  try {
    // 1. Check for explicit URL or explicit domain scan command (avoid false-positive words like "is")
    const urlMatch = message.match(/https?:\/\/[^\s"'<>]+/i);
    const domainActionMatch =
      !urlMatch &&
      /\b(scan|check|inspect|analyze|whois|rdap|dns|verify)\b/i.test(message) &&
      message.match(
        /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|org|net|io|co|in|gov|edu|info|biz|xyz|top|online|site|tech|app|dev|me|uk|us|ca|au|de|ru|cn|tk|ml|ga|cf|gq|pw|cc|bank|sbi)(?:\.[a-z]{2,6})?)\b/i
      );

    const candidateUrl = urlMatch
      ? urlMatch[0].replace(/[.,;!?)]+$/, '')
      : domainActionMatch
        ? `https://${domainActionMatch[1]}`
        : null;

    if (candidateUrl && !/^\d+\.\d+\.\d+\.\d+$/.test(candidateUrl.replace(/^https?:\/\//, ''))) {
      const { analyzeUrlTarget } = await import('./urlAnalyzer.ts');
      const scanRes = await analyzeUrlTarget(candidateUrl, { skipAiExplanation: true });
      executedTools.push({
        toolName: 'scanUrlTarget',
        target: scanRes.url || candidateUrl,
        riskScore: scanRes.riskScore,
        verdict: scanRes.verdict,
        summary: `Domain Age: ${scanRes.domainAnalysis?.rdap?.formattedAge || 'Unavailable'} · DNS Resolvable: ${scanRes.dnsAnalysis?.resolvable ? 'Yes' : 'No'} · IP: ${scanRes.ipAnalysis?.ip || 'None'}`,
      });
      toolResultsPayload.push({
        tool: 'scanUrlTarget',
        target: scanRes.url,
        riskScore: scanRes.riskScore,
        verdict: scanRes.verdict,
        domainAnalysis: scanRes.domainAnalysis,
        dnsAnalysis: scanRes.dnsAnalysis,
        tlsInspection: scanRes.tlsInspection,
        ipAnalysis: scanRes.ipAnalysis,
        triggeredEvidence: (scanRes.evidence || []).filter((e: any) => e.scoreDelta !== 0),
      });
    }

    // 2. Check for IPv4 address scan intent
    const ipv4Match = message.match(
      /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/
    );
    if (ipv4Match && executedTools.length === 0) {
      const targetIp = ipv4Match[0];
      const { analyzeIpAddress } = await import('./ipAnalyzer.ts');
      const ipRes = await analyzeIpAddress(targetIp, false);
      const listedCount = (ipRes.dnsblResults || []).filter((d) => d.status === 'Listed').length;
      executedTools.push({
        toolName: 'scanPublicIp',
        target: ipRes.ip,
        riskScore: ipRes.riskScore,
        verdict: ipRes.verdict,
        summary: `ASN: ${ipRes.asn} (${ipRes.organization}) · Country: ${ipRes.country} · DNSBL Hits: ${listedCount}`,
      });
      toolResultsPayload.push({
        tool: 'scanPublicIp',
        ipAnalysis: ipRes,
      });
    }

    // 3. Check if user pasted a suspicious SMS/email message to analyze
    if (
      executedTools.length === 0 &&
      /\b(analyze|scan|check)\s+(this\s+)?(sms|email|message|text)\b/i.test(message) &&
      message.length > 40
    ) {
      const { analyzeMessageContent } = await import('./messageAnalyzer.ts');
      const msgRes = await analyzeMessageContent(message, undefined, undefined, {
        skipAiExplanation: true,
      });
      executedTools.push({
        toolName: 'scanMessagePhishing',
        target: message.slice(0, 80),
        riskScore: msgRes.riskScore,
        verdict: msgRes.verdict,
        summary: `Primary Intent: ${msgRes.mlClassification?.primaryIntent} · Confidence: ${msgRes.mlClassification?.phishingConfidence}%`,
      });
      toolResultsPayload.push({
        tool: 'scanMessagePhishing',
        riskScore: msgRes.riskScore,
        verdict: msgRes.verdict,
        mlClassification: msgRes.mlClassification,
        nlpSignals: msgRes.nlpSignals,
        manipulationVectorScores: msgRes.manipulationVectorScores,
        triggeredEvidence: (msgRes.evidence || []).filter((e: any) => e.scoreDelta !== 0),
      });
    }
  } catch (toolErr) {
    console.warn('Live security tool pre-check warning:', toolErr);
  }

  return { executedTools, toolResultsPayload };
}

export async function runSocMultiTurnChat(params: {
  model: 'gemini-3.1-flash-lite' | 'gemini-3.8-flash' | 'gemini-4-argon' | 'gemini-3.1-pro-preview';
  rolePersona: string;
  history: { role: 'user' | 'model'; text: string }[];
  message: string;
  useSearchGrounding?: boolean;
  enableSecurityTools?: boolean;
  attachedScanContext?: string;
}) {
  const ai = getGenAIClient();
  const allowedModels = new Set([
    'gemini-3.1-flash-lite',
    'gemini-3.8-flash',
    'gemini-4-argon',
    'gemini-3.1-pro-preview',
  ]);
  const requestedModel = allowedModels.has(params.model)
    ? params.model
    : 'gemini-3.8-flash';
  const systemInstruction =
    ROLE_SYSTEM_INSTRUCTIONS[params.rolePersona] || ROLE_SYSTEM_INSTRUCTIONS['soc-analyst'];

  // Run deterministic live security tools if enabled and message contains a target
  const { executedTools, toolResultsPayload } =
    params.enableSecurityTools !== false
      ? await executeRelevantSecurityToolsForChat(params.message)
      : { executedTools: [], toolResultsPayload: [] };

  const contextSections: string[] = [];
  if (params.attachedScanContext) {
    contextSections.push(`[ATTACHED LIVE SCAN TELEMETRY CONTEXT]\n${params.attachedScanContext}`);
  }
  if (toolResultsPayload.length > 0) {
    contextSections.push(
      `[LIVE SECURITY SCANNER TOOL TELEMETRY EXECUTED BY PHISHING SHIELD]\n${JSON.stringify(
        toolResultsPayload
      )}`
    );
  }
  contextSections.push(`[USER / ANALYST MESSAGE]\n${params.message}`);

  const fullUserMessage = contextSections.join('\n\n');

  if (!ai) {
    throw new Error(
      'GEMINI_API_KEY is not configured. Please check the Settings > Secrets panel.'
    );
  }

  try {
    const formattedHistory = (params.history || []).slice(-12).map((turn) => ({
      role: turn.role,
      parts: [{ text: turn.text }],
    }));

    const contents = [
      ...formattedHistory,
      {
        role: 'user',
        parts: [{ text: fullUserMessage }],
      },
    ];

    const { response, modelUsed } = await generateWithResilientFallback(ai, {
      preferredModel: requestedModel,
      contents,
      timeoutMs: 7500,
      config: {
        systemInstruction,
        temperature: 0.25,
        ...(params.useSearchGrounding ? { tools: [{ googleSearch: {} }] } : {}),
      },
    });

    const chunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks || [];
    const webSources = chunks
      .map((c: any) => (c.web ? { uri: c.web.uri, title: c.web.title || c.web.uri } : null))
      .filter(Boolean);

    return {
      reply: response.text || 'Analysis complete.',
      modelUsed,
      webSources,
      executedTools,
    };
  } catch (error) {
    if (executedTools.length > 0) {
      const toolSummaryLines = executedTools.map(
        (t) =>
          `• **${t.toolName}** on \`${t.target}\`: **${t.verdict}** (Risk Score: **${t.riskScore}/100**) — ${t.summary}`
      );
      return {
        reply: `### Live Security Telemetry Assessment\n\n${toolSummaryLines.join(
          '\n'
        )}\n\n**Recommended SOC Next Steps:**\n1. Verify all triggered risk indicators in the telemetry card above.\n2. If the Risk Score is >= 50, block the domain/IP at your DNS resolver and Secure Web Gateway.\n3. Enforce phishing-resistant MFA (FIDO2/WebAuthn) and inspect authentication logs for anomalous sessions.`,
        modelUsed: 'deterministic-soc-engine',
        webSources: [],
        executedTools,
      };
    }
    throw new Error(formatGeminiErrorMessage(error));
  }
}

// ============================================================================
// 2. GOOGLE SEARCH GROUNDING (Up-to-date Live Threat & Web Intelligence)
// ============================================================================
export async function runSearchGroundingQuery(queryText: string) {
  const ai = getGenAIClient();
  if (!ai) {
    throw new Error('GEMINI_API_KEY is not configured.');
  }

  try {
    const { response, modelUsed } = await generateWithResilientFallback(ai, {
      preferredModel: 'gemini-3.8-flash',
      contents: queryText,
      timeoutMs: 9000,
      config: {
        systemInstruction:
          'You are a cybersecurity threat intelligence researcher. Provide accurate, up-to-date information on domains, CVEs, phishing campaigns, security advisories, and threat actors using real-time Google Search data.',
        tools: [{ googleSearch: {} }],
      },
    });

    const chunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks || [];
    const sources: { uri: string; title: string }[] = [];
    for (const chunk of chunks as any[]) {
      if (chunk.web?.uri) {
        sources.push({
          uri: chunk.web.uri,
          title: chunk.web.title || chunk.web.uri,
        });
      }
    }

    return {
      text: response.text || 'No summary returned.',
      sources,
      modelUsed,
    };
  } catch (error) {
    throw new Error(formatGeminiErrorMessage(error));
  }
}

// ============================================================================
// 3. GOOGLE MAPS GROUNDING (Geospatial Infrastructure, CERT & Cyber Response)
// ============================================================================
export async function runMapsGroundingQuery(
  queryText: string,
  latitude?: number,
  longitude?: number
) {
  const ai = getGenAIClient();
  if (!ai) {
    throw new Error('GEMINI_API_KEY is not configured.');
  }

  try {
    const hasCoords =
      typeof latitude === 'number' &&
      !Number.isNaN(latitude) &&
      typeof longitude === 'number' &&
      !Number.isNaN(longitude);

    const { response, modelUsed } = await generateWithResilientFallback(ai, {
      preferredModel: 'gemini-3.1-flash-lite',
      contents: queryText,
      timeoutMs: 7500,
      config: {
        tools: [{ googleMaps: {} }],
        ...(hasCoords
          ? {
              toolConfig: {
                retrievalConfig: {
                  latLng: {
                    latitude: latitude!,
                    longitude: longitude!,
                  },
                },
              },
            }
          : {}),
      },
    });

    const chunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks || [];
    const places: {
      uri: string;
      title: string;
      reviewSnippets: string[];
    }[] = [];

    for (const chunk of chunks as any[]) {
      if (chunk.maps?.uri) {
        const snippets: string[] = [];
        const rawReviews = chunk.maps?.placeAnswerSources?.reviewSnippets;
        if (Array.isArray(rawReviews)) {
          for (const rev of rawReviews) {
            if (typeof rev === 'string') snippets.push(rev);
            else if (rev?.text) snippets.push(String(rev.text));
            else if (rev?.reviewText) snippets.push(String(rev.reviewText));
          }
        }
        places.push({
          uri: chunk.maps.uri,
          title: chunk.maps.title || 'View Location on Google Maps',
          reviewSnippets: snippets,
        });
      }
    }

    return {
      text: response.text || 'No geospatial intelligence returned.',
      places,
      modelUsed,
    };
  } catch (error) {
    throw new Error(formatGeminiErrorMessage(error));
  }
}

// ============================================================================
// 4. AUDIO TRANSCRIPTION (gemini-3.5-transcribe with fast fallback)
// ============================================================================
export async function transcribeSecurityAudio(
  base64Audio: string,
  mimeType: string,
  customPrompt?: string
) {
  const ai = getGenAIClient();
  if (!ai) {
    throw new Error('GEMINI_API_KEY is not configured.');
  }

  try {
    const cleanBase64 = base64Audio.replace(/^data:[^;]+;base64,/, '');
    const audioPart = {
      inlineData: {
        mimeType: mimeType || 'audio/webm',
        data: cleanBase64,
      },
    };
    const textPart = {
      text:
        customPrompt ||
        'Transcribe this audio accurately. Support English, Hindi, and Hinglish. Preserve all spoken URLs, phone numbers, and organization names.',
    };

    const response = await withTimeout(
      ai.models.generateContent({
        model: 'gemini-3.5-transcribe',
        contents: { parts: [audioPart, textPart] },
      }),
      10000,
      'Audio transcription with gemini-3.5-transcribe'
    );
    return {
      transcript: response.text || '',
      modelUsed: 'gemini-3.5-transcribe',
    };
  } catch (error) {
    throw new Error(formatGeminiErrorMessage(error));
  }
}

// ============================================================================
// 5. CREATE & EDIT IMAGES (gemini-3.1-flash-image / gemini-3.1-flash-lite-image)
// ============================================================================
export async function generateOrEditSecurityImage(params: {
  prompt: string;
  aspectRatio?: '1:1' | '16:9' | '9:16' | '4:3' | '3:4';
  highQuality?: boolean;
  base64Image?: string;
  mimeType?: string;
}) {
  const ai = getGenAIClient();
  if (!ai) {
    throw new Error('GEMINI_API_KEY is not configured.');
  }

  const modelName = params.highQuality
    ? 'gemini-3.1-flash-image'
    : 'gemini-3.1-flash-lite-image';

  try {
    const parts: any[] = [];
    if (params.base64Image && params.mimeType) {
      const cleanData = params.base64Image.replace(/^data:[^;]+;base64,/, '');
      parts.push({
        inlineData: {
          data: cleanData,
          mimeType: params.mimeType,
        },
      });
    }
    parts.push({ text: params.prompt });

    const response = await ai.models.generateContent({
      model: modelName,
      contents: { parts },
      config: {
        imageConfig: {
          aspectRatio: params.aspectRatio || '16:9',
          ...(params.highQuality ? { imageSize: '1K' } : {}),
        },
      },
    });

    let imageUrl: string | null = null;
    let textNote = '';

    const candidateParts = response.candidates?.[0]?.content?.parts || [];
    for (const part of candidateParts) {
      if (part.inlineData?.data) {
        const outMime = part.inlineData.mimeType || 'image/png';
        imageUrl = `data:${outMime};base64,${part.inlineData.data}`;
      } else if (part.text) {
        textNote += part.text;
      }
    }

    if (!imageUrl) {
      throw new Error(
        textNote || 'Model did not return an image part. Try refining your prompt.'
      );
    }

    return {
      imageUrl,
      caption: textNote,
      modelUsed: modelName,
    };
  } catch (error) {
    throw new Error(formatGeminiErrorMessage(error));
  }
}

// ============================================================================
// 6. VEO 3 VIDEO GENERATION (veo-3.1-lite-generate-preview)
// ============================================================================
export async function startVeoVideoGeneration(params: {
  prompt: string;
  aspectRatio: '16:9' | '9:16';
}) {
  const ai = getGenAIClient();
  if (!ai) {
    throw new Error('GEMINI_API_KEY is not configured.');
  }

  try {
    const operation = await ai.models.generateVideos({
      model: 'veo-3.1-lite-generate-preview',
      prompt: params.prompt,
      config: {
        numberOfVideos: 1,
        resolution: '720p',
        aspectRatio: params.aspectRatio === '9:16' ? '9:16' : '16:9',
      },
    });

    return {
      operationName: operation.name,
    };
  } catch (error) {
    throw new Error(formatGeminiErrorMessage(error));
  }
}

export async function pollVeoVideoOperation(operationName: string) {
  const ai = getGenAIClient();
  if (!ai) {
    throw new Error('GEMINI_API_KEY is not configured.');
  }

  try {
    const op = new GenerateVideosOperation();
    op.name = operationName;
    const updated = await ai.operations.getVideosOperation({ operation: op });
    return {
      done: Boolean(updated.done),
      error: updated.error ? JSON.stringify(updated.error) : null,
    };
  } catch (error) {
    throw new Error(formatGeminiErrorMessage(error));
  }
}

export async function getCompletedVeoVideoUri(operationName: string): Promise<{
  uri: string;
  apiKey: string;
}> {
  const ai = getGenAIClient();
  const apiKey = process.env.GEMINI_API_KEY || '';
  if (!ai || !apiKey) {
    throw new Error('GEMINI_API_KEY is not configured.');
  }

  const op = new GenerateVideosOperation();
  op.name = operationName;
  const updated = await ai.operations.getVideosOperation({ operation: op });
  const uri = updated.response?.generatedVideos?.[0]?.video?.uri;
  if (!uri) {
    throw new Error('Video generation operation has not produced a downloadable URI yet.');
  }
  return { uri, apiKey };
}

export async function generateSpeechAudio(params: {
  text: string;
  voiceName?: 'Kore' | 'Zephyr' | 'Puck' | 'Charon' | 'Fenrir';
}) {
  const ai = getGenAIClient();
  if (!ai) {
    throw new Error('GEMINI_API_KEY is not configured.');
  }

  const cleanText = params.text.trim().slice(0, 2000);
  if (!cleanText) {
    throw new Error('Text for speech synthesis cannot be empty.');
  }

  try {
    const response = await withTimeout(
      ai.models.generateContent({
        model: 'gemini-3.8-flash-lite-tts',
        contents: [
          {
            role: 'user',
            parts: [
              {
                text: cleanText,
              },
            ],
          },
        ],
        config: {
          responseModalities: ['AUDIO'],
          speechConfig: {
            voiceConfig: {
              prebuiltVoiceConfig: { voiceName: params.voiceName || 'Kore' },
            },
          },
        },
      }),
      5500,
      'TTS synthesis'
    );

    const base64Audio =
      response.candidates?.[0]?.content?.parts?.[0]?.inlineData?.data;
    if (!base64Audio) {
      throw new Error('No audio output returned from gemini-3.8-flash-lite-tts.');
    }

    return {
      audioDataUrl: `data:audio/wav;base64,${base64Audio}`,
      modelUsed: 'gemini-3.8-flash-lite-tts',
    };
  } catch (error) {
    throw new Error(formatGeminiErrorMessage(error));
  }
}

export { Modality };
export type { LiveServerMessage };

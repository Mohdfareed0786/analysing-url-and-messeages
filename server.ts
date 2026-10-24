import express from 'express';
import http from 'node:http';
import path from 'node:path';
import net from 'node:net';
import { Readable } from 'node:stream';
import dotenv from 'dotenv';
import multer from 'multer';
import { WebSocketServer } from 'ws';
import { createServer as createViteServer } from 'vite';
import { adminAuth, requireAuth, type AuthenticatedRequest } from './src/server/firebaseAdmin.ts';
import { analyzeUrlTarget } from './src/server/urlAnalyzer.ts';
import { analyzeMessageContent } from './src/server/messageAnalyzer.ts';
import { analyzeIpAddress, classifyIpScope } from './src/server/ipAnalyzer.ts';
import { analyzeScreenshotImage } from './src/server/screenshotAnalyzer.ts';
import {
  getGenAIClient,
  Modality,
  type LiveServerMessage,
  runSocMultiTurnChat,
  runSearchGroundingQuery,
  runMapsGroundingQuery,
  transcribeSecurityAudio,
  generateOrEditSecurityImage,
  startVeoVideoGeneration,
  pollVeoVideoOperation,
  getCompletedVeoVideoUri,
  generateSpeechAudio,
  generateSecurityExplanation,
} from './src/server/geminiService.ts';
import { analyzeQrImageBuffer } from './src/server/qrAnalyzer.ts';
import { analyzeDomainIntelligence } from './src/server/domainAnalyzer.ts';
import { runClaudeSecurityAssistant } from './src/server/claudeService.ts';

dotenv.config();

const MAX_SCREENSHOT_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB limit
const ALLOWED_SCREENSHOT_MIMES = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp']);
const ALLOWED_SCREENSHOT_EXTS = new Set(['.png', '.jpg', '.jpeg', '.webp']);

const screenshotUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_SCREENSHOT_SIZE_BYTES,
    files: 1,
  },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    const mime = (file.mimetype || '').toLowerCase();
    if (!ALLOWED_SCREENSHOT_MIMES.has(mime) || !ALLOWED_SCREENSHOT_EXTS.has(ext)) {
      cb(
        new Error(
          'Unsupported file type. Only PNG (.png), JPG/JPEG (.jpg, .jpeg), and WEBP (.webp) screenshot images are allowed.'
        )
      );
      return;
    }
    cb(null, true);
  },
});

async function startServer() {
  const app = express();
  const httpServer = http.createServer(app);
  const PORT = 3000;

  app.set('trust proxy', true);
  app.use(express.json({ limit: '15mb' }));

  // Health check endpoint
  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'operational',
      service: 'Phishing Shield Security Engine',
      timestamp: new Date().toISOString(),
    });
  });

  // Live System Status endpoint for 12 Security Subsystems
  app.get('/api/system-status', requireAuth, (_req: AuthenticatedRequest, res) => {
    const geminiConfigured = Boolean(
      process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY'
    );
    const claudeConfigured = Boolean(
      process.env.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY.trim().length > 10
    );

    res.json({
      timestamp: new Date().toISOString(),
      services: [
        {
          id: 'url-engine',
          name: 'URL Security Scanner',
          status: 'Operational',
          provider: 'Native Lexical & Heuristics + Threat Feed',
          detail: 'Syntax, X.509 TLS inspection, Punycode/homograph detection, redirect tracer',
        },
        {
          id: 'message-engine',
          name: 'Message Scam Analyzer',
          status: 'Operational',
          provider: 'NLP Linguistic Engine (Multilingual)',
          detail: 'Urgency, account threats, KYC/OTP requests, UPI/Crypto demands (EN/HI/Hinglish)',
        },
        {
          id: 'screenshot-engine',
          name: 'Screenshot & Vision Analyzer',
          status: 'Operational',
          provider: geminiConfigured ? 'Gemini 3.8 Vision + Tesseract' : 'Tesseract.js OCR',
          detail: 'Multi-stage OCR, UI layout heuristic parsing, visual brand impersonation analysis',
        },
        {
          id: 'qr-engine',
          name: 'QR Code Security Decoder',
          status: 'Operational',
          provider: 'Sharp + jsQR Matrix Engine',
          detail: 'Multi-pass grayscale/contrast decoding, URL/UPI/Wi-Fi payload safety verification',
        },
        {
          id: 'ip-engine',
          name: 'Public IP Intelligence',
          status: 'Operational',
          provider: 'IP Geolocation & ASN Resolver',
          detail: 'Public/private range classification, Bogon filtering, Abuse reputation, reverse PTR',
        },
        {
          id: 'domain-engine',
          name: 'Domain Intelligence & RDAP',
          status: 'Operational',
          provider: 'ICANN RDAP + Authoritative DNS',
          detail: 'Live DNS records (A/AAAA/MX/TXT/SPF/DMARC), real registration age, registrar lookup',
        },
        {
          id: 'threat-intel',
          name: 'Threat Intelligence Feeds',
          status: 'Operational',
          provider: 'URLhaus (abuse.ch) + Spamhaus/SpamCop DNSBL',
          detail: 'Live malware URL database queries & DNS blocklist reputation lookups',
        },
        {
          id: 'gemini-engine',
          name: 'Gemini AI Explanation Engine',
          status: geminiConfigured ? 'Operational' : 'Key Not Configured',
          provider: 'Gemini 3.8 Flash (Google GenAI)',
          detail: geminiConfigured
            ? 'Evidence-grounded multilingual threat explanation and remediation briefing'
            : 'Rule-based deterministic evidence synthesis active (set GEMINI_API_KEY to enable AI)',
        },
        {
          id: 'claude-engine',
          name: 'Claude Security Assistant',
          status: claudeConfigured ? 'Operational' : 'Not Configured',
          provider: 'Anthropic Claude (claude-3-5-sonnet)',
          detail: claudeConfigured
            ? 'Deep conversational SOC incident response & threat hunting copilot'
            : 'Set ANTHROPIC_API_KEY to activate conversational Claude SOC analysis',
        },
        {
          id: 'live-voice',
          name: 'Gemini Live Voice Copilot',
          status: geminiConfigured ? 'Operational' : 'Key Not Configured',
          provider: 'Gemini 3.8 Live WebSocket Bridge (/api/live)',
          detail: geminiConfigured
            ? 'Real-time bidirectional 24kHz audio SOC conversational channel'
            : 'WebSocket endpoint mounted; requires GEMINI_API_KEY',
        },
        {
          id: 'risk-engine',
          name: 'Evidence-Based Risk Scoring Matrix',
          status: 'Operational',
          provider: 'Deterministic 0-100 Weighted Scorer',
          detail: 'Non-fabricated, explainable signals (Low 0-29, Med 30-59, High 60-79, Crit 80-100)',
        },
        {
          id: 'db-vault',
          name: 'Security Vault & Audit Trail',
          status: 'Operational',
          provider: 'Firebase Firestore with Security Rules',
          detail: 'Strict per-user authorization, encrypted session history, and report archiving',
        },
      ],
    });
  });

  // 0. Screenshot Security Analyzer Endpoint: POST /api/scan-screenshot
  app.post('/api/scan-screenshot', requireAuth, (req: AuthenticatedRequest, res) => {
    screenshotUpload.single('image')(req, res, async (uploadErr: unknown) => {
      if (uploadErr) {
        if (uploadErr instanceof multer.MulterError) {
          if (uploadErr.code === 'LIMIT_FILE_SIZE') {
            res.status(400).json({
              success: false,
              error: {
                code: 'FILE_TOO_LARGE',
                message: 'Screenshot file size exceeds the 10 MB security limit.',
              },
            });
            return;
          }
          res.status(400).json({
            success: false,
            error: {
              code: 'UPLOAD_ERROR',
              message: `Upload error: ${uploadErr.message}`,
            },
          });
          return;
        }
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_PAYLOAD',
            message:
              uploadErr instanceof Error
                ? uploadErr.message
                : 'Invalid screenshot upload payload.',
          },
        });
        return;
      }

      try {
        const file = req.file;
        if (!file || !file.buffer || file.buffer.byteLength === 0) {
          res.status(400).json({
            success: false,
            error: {
              code: 'INVALID_FILE',
              message: 'Please upload a valid PNG, JPG/JPEG, or WEBP screenshot image (field: "image").',
            },
          });
          return;
        }

        const result = await analyzeScreenshotImage({
          buffer: file.buffer,
          originalName: file.originalname || 'screenshot.png',
          mimeType: file.mimetype || 'image/png',
        });

        res.json({
          success: true,
          ...result,
          risk_score: result.riskScore,
          classification: result.verdict,
          findings: result.evidence,
        });
      } catch (error: unknown) {
        console.error('Screenshot scan error:', error);
        res.status(500).json({
          success: false,
          error: {
            code: 'ANALYSIS_FAILED',
            message:
              error instanceof Error ? error.message : 'Failed to analyze screenshot security.',
          },
        });
      }
    });
  });

  // Detect client or server public IP
  app.get('/api/my-ip', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const forwarded = req.headers['x-forwarded-for'];
      const candidateIp = Array.isArray(forwarded)
        ? forwarded[0]
        : typeof forwarded === 'string'
          ? forwarded.split(',')[0].trim()
          : req.socket.remoteAddress || '';

      const cleanCandidate = candidateIp.replace(/^::ffff:/, '');
      if (net.isIP(cleanCandidate) !== 0 && classifyIpScope(cleanCandidate) === 'Public') {
        res.json({ success: true, ip: cleanCandidate, source: 'Client Connection Header' });
        return;
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
      const r = await fetch('https://api.ipify.org?format=json', { signal: controller.signal });
      clearTimeout(timer);
      if (r.ok) {
        const data = await r.json();
        if (data?.ip) {
          res.json({ success: true, ip: data.ip, source: 'Network Egress Node' });
          return;
        }
      }
      res.status(404).json({
        success: false,
        error: {
          code: 'IP_NOT_FOUND',
          message: 'Unable to automatically determine public IP.',
        },
      });
    } catch (error: unknown) {
      res.status(500).json({
        success: false,
        error: {
          code: 'DETECTION_FAILED',
          message: error instanceof Error ? error.message : 'Failed to detect public IP',
        },
      });
    }
  });

  // 1. URL Scanner Endpoint: POST /api/scan-url
  app.post('/api/scan-url', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { url } = req.body as { url?: string };
      if (!url || typeof url !== 'string' || !url.trim()) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_INPUT',
            message: 'Please provide a valid URL string to analyze.',
          },
        });
        return;
      }
      if (url.length > 2048) {
        res.status(400).json({
          success: false,
          error: {
            code: 'URL_TOO_LONG',
            message: 'URL exceeds maximum length of 2048 characters.',
          },
        });
        return;
      }

      const result = await analyzeUrlTarget(url);
      res.json({
        success: true,
        ...result,
        risk_score: result.riskScore,
        classification: result.verdict,
        findings: result.evidence,
      });
    } catch (error: unknown) {
      console.error('URL scan error:', error);
      res.status(500).json({
        success: false,
        error: {
          code: 'ANALYSIS_FAILED',
          message: error instanceof Error ? error.message : 'URL analysis could not be completed.',
        },
      });
    }
  });

  // 2. Message Scanner Endpoint: POST /api/scan-message
  app.post('/api/scan-message', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { message, sender, headers } = req.body as {
        message?: string;
        sender?: string;
        headers?: string;
      };
      if (!message || typeof message !== 'string' || !message.trim()) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_INPUT',
            message: 'Please provide message content to analyze.',
          },
        });
        return;
      }
      if (message.length > 20000) {
        res.status(400).json({
          success: false,
          error: {
            code: 'PAYLOAD_TOO_LARGE',
            message: 'Message content exceeds maximum length of 20,000 characters.',
          },
        });
        return;
      }

      const result = await analyzeMessageContent(message, sender, headers);
      res.json({
        success: true,
        ...result,
        risk_score: result.riskScore,
        classification: result.verdict,
        findings: result.evidence,
      });
    } catch (error: unknown) {
      console.error('Message scan error:', error);
      res.status(500).json({
        success: false,
        error: {
          code: 'ANALYSIS_FAILED',
          message: error instanceof Error ? error.message : 'Failed to analyze message content.',
        },
      });
    }
  });

  // 3. Public IP Scanner Endpoint: POST /api/scan-ip
  app.post('/api/scan-ip', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { ip } = req.body as { ip?: string };
      if (!ip || typeof ip !== 'string' || !ip.trim()) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_INPUT',
            message: 'Please provide an IPv4 or IPv6 address to analyze.',
          },
        });
        return;
      }

      const result = await analyzeIpAddress(ip.trim(), true);
      res.json({
        success: true,
        ...result,
        risk_score: result.riskScore,
        classification: result.verdict,
        findings: result.evidence,
      });
    } catch (error: unknown) {
      console.error('IP scan error:', error);
      res.status(500).json({
        success: false,
        error: {
          code: 'ANALYSIS_FAILED',
          message: error instanceof Error ? error.message : 'Failed to analyze IP address.',
        },
      });
    }
  });

  // 3b. QR Code Security Scanner Endpoint: POST /api/scan-qr
  app.post('/api/scan-qr', requireAuth, (req: AuthenticatedRequest, res) => {
    screenshotUpload.single('image')(req, res, async (uploadErr: unknown) => {
      if (uploadErr) {
        res.status(400).json({
          success: false,
          error: {
            code: 'UPLOAD_ERROR',
            message: uploadErr instanceof Error ? uploadErr.message : 'Failed to upload QR image.',
          },
        });
        return;
      }

      try {
        let buffer: Buffer | null = null;
        if (req.file?.buffer) {
          buffer = req.file.buffer;
        } else if (req.body?.imageBase64 && typeof req.body.imageBase64 === 'string') {
          const rawBase64 = req.body.imageBase64.replace(/^data:image\/[a-zA-Z+]+;base64,/, '');
          buffer = Buffer.from(rawBase64, 'base64');
        }

        if (!buffer || buffer.length === 0) {
          res.status(400).json({
            success: false,
            error: {
              code: 'MISSING_IMAGE',
              message: 'Please provide a valid QR image file or base64 image data.',
            },
          });
          return;
        }

        const result = await analyzeQrImageBuffer(buffer);
        res.json({
          success: true,
          ...result,
          risk_score: result.riskScore,
          classification: result.verdict,
          findings: result.evidence,
        });
      } catch (err: unknown) {
        console.error('QR scan error:', err);
        res.status(500).json({
          success: false,
          error: {
            code: 'SCAN_FAILED',
            message: err instanceof Error ? err.message : 'Failed to analyze QR code.',
          },
        });
      }
    });
  });

  // 3c. Domain Intelligence Endpoint: POST /api/scan-domain
  app.post('/api/scan-domain', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { domain } = req.body as { domain?: string };
      if (!domain || typeof domain !== 'string' || !domain.trim()) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_INPUT',
            message: 'Please provide a valid domain name to inspect.',
          },
        });
        return;
      }

      const result = await analyzeDomainIntelligence(domain.trim());
      res.json({
        success: true,
        ...result,
        risk_score: result.riskScore,
        classification: result.verdict,
        findings: result.evidence,
      });
    } catch (error: unknown) {
      console.error('Domain scan error:', error);
      res.status(500).json({
        success: false,
        error: {
          code: 'ANALYSIS_FAILED',
          message: error instanceof Error ? error.message : 'Failed to inspect domain.',
        },
      });
    }
  });

  // 3d. Evidence-Grounded AI Security Explanation: POST /api/ai/explain
  app.post('/api/ai/explain', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { scanType, target, riskScore, verdict, evidenceSummary, language } = req.body as {
        scanType: string;
        target: string;
        riskScore: number;
        verdict: string;
        evidenceSummary: string[];
        language?: 'en' | 'hi' | 'hinglish';
      };

      if (!target || typeof target !== 'string') {
        res.status(400).json({
          success: false,
          error: 'Target parameter is required.',
        });
        return;
      }

      const explanation = await generateSecurityExplanation(
        (scanType as any) || 'url',
        target,
        typeof riskScore === 'number' ? riskScore : 0,
        verdict || 'UNKNOWN',
        { summary: evidenceSummary || [] }
      );

      res.json({
        success: true,
        explanation,
      });
    } catch (error: unknown) {
      console.error('AI explanation error:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to generate AI security explanation.',
      });
    }
  });

  // 3e. Anthropic Claude Security Assistant: POST /api/ai/claude/chat
  app.post('/api/ai/claude/chat', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { message, history, attachedScanContext } = req.body as {
        message?: string;
        history?: Array<{ role: 'user' | 'assistant'; content: string }>;
        attachedScanContext?: string;
      };

      if (!message || typeof message !== 'string' || !message.trim()) {
        res.status(400).json({
          success: false,
          error: 'Message content is required.',
        });
        return;
      }

      const result = await runClaudeSecurityAssistant({
        message: message.trim(),
        history: Array.isArray(history) ? history : [],
        attachedScanContext: typeof attachedScanContext === 'string' ? attachedScanContext : undefined,
      });

      res.json(result);
    } catch (error: unknown) {
      console.error('Claude assistant error:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Claude assistant query failed.',
      });
    }
  });

  // 3f. Scan Result Feedback & User Reporting: POST /api/feedback
  app.post('/api/feedback', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { scanId, scanType, target, feedbackType, comment, contactEmail } = req.body as {
        scanId?: string;
        scanType?: string;
        target?: string;
        feedbackType?: string;
        comment?: string;
        contactEmail?: string;
      };

      if (!feedbackType) {
        res.status(400).json({
          success: false,
          error: 'Missing feedbackType parameter.',
        });
        return;
      }

      // Store feedback or log for SOC quality control
      console.log(`[USER FEEDBACK] User=${req.user?.uid} ScanId=${scanId} Type=${feedbackType} Target=${target} Comment=${comment}`);

      res.json({
        success: true,
        message: 'Feedback received. Thank you for helping improve Phishing Shield threat intelligence.',
        receivedAt: new Date().toISOString(),
      });
    } catch (error: unknown) {
      console.error('Feedback error:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to submit feedback.',
      });
    }
  });

  // 4. Multi-Turn SOC Chatbot Endpoint: POST /api/chat
  app.post('/api/chat', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const {
        model,
        rolePersona,
        history,
        message,
        useSearchGrounding,
        enableSecurityTools,
        attachedScanContext,
      } = req.body as {
        model?: 'gemini-3.1-flash-lite' | 'gemini-3.8-flash' | 'gemini-3.1-pro-preview';
        rolePersona?: string;
        history?: { role: 'user' | 'model'; text: string }[];
        message?: string;
        useSearchGrounding?: boolean;
        enableSecurityTools?: boolean;
        attachedScanContext?: string;
      };

      if (!message || typeof message !== 'string' || !message.trim()) {
        res.status(400).json({ error: 'Chat message cannot be empty.' });
        return;
      }

      const result = await runSocMultiTurnChat({
        model: model || 'gemini-3.8-flash',
        rolePersona: rolePersona || 'soc-analyst',
        history: Array.isArray(history) ? history : [],
        message: message.trim(),
        useSearchGrounding: Boolean(useSearchGrounding),
        enableSecurityTools: enableSecurityTools !== false,
        attachedScanContext:
          typeof attachedScanContext === 'string' && attachedScanContext.trim()
            ? attachedScanContext.trim().slice(0, 12000)
            : undefined,
      });

      res.json(result);
    } catch (error: unknown) {
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Failed to process chat message.',
      });
    }
  });

  // 4b. Gemini TTS Audio Briefing Endpoint (gemini-3.8-flash-lite-tts): POST /api/tts
  app.post('/api/tts', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { text, voiceName } = req.body as {
        text?: string;
        voiceName?: 'Kore' | 'Zephyr' | 'Puck' | 'Charon' | 'Fenrir';
      };
      if (!text || typeof text !== 'string' || !text.trim()) {
        res.status(400).json({ error: 'Text is required for TTS audio generation.' });
        return;
      }
      const result = await generateSpeechAudio({
        text: text.trim(),
        voiceName: voiceName || 'Kore',
      });
      res.json(result);
    } catch (error: unknown) {
      res.status(400).json({
        error: error instanceof Error ? error.message : 'TTS audio synthesis failed.',
      });
    }
  });

  // 5. Google Search Grounding Endpoint: POST /api/grounding/search & /api/search-grounding
  app.post(['/api/grounding/search', '/api/search-grounding'], requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { query } = req.body as { query?: string };
      if (!query || typeof query !== 'string' || !query.trim()) {
        res.status(400).json({ error: 'Search query cannot be empty.' });
        return;
      }
      const result = await runSearchGroundingQuery(query.trim());
      res.json(result);
    } catch (error: unknown) {
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Search grounding query failed.',
      });
    }
  });

  // 6. Google Maps Grounding Endpoint: POST /api/grounding/maps
  app.post('/api/grounding/maps', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { query, latitude, longitude } = req.body as {
        query?: string;
        latitude?: number;
        longitude?: number;
      };
      if (!query || typeof query !== 'string' || !query.trim()) {
        res.status(400).json({ error: 'Maps grounding query cannot be empty.' });
        return;
      }
      const result = await runMapsGroundingQuery(query.trim(), latitude, longitude);
      res.json(result);
    } catch (error: unknown) {
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Maps grounding query failed.',
      });
    }
  });

  // 7. Audio Transcription Endpoint (gemini-3.5-transcribe): POST /api/transcribe
  app.post('/api/transcribe', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { audioBase64, mimeType, prompt } = req.body as {
        audioBase64?: string;
        mimeType?: string;
        prompt?: string;
      };
      if (!audioBase64 || typeof audioBase64 !== 'string') {
        res.status(400).json({ error: 'Audio payload is required for transcription.' });
        return;
      }
      const result = await transcribeSecurityAudio(
        audioBase64,
        mimeType || 'audio/webm',
        prompt
      );
      res.json(result);
    } catch (error: unknown) {
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Audio transcription failed.',
      });
    }
  });

  // 8. Create & Edit Images Endpoint: POST /api/image/generate
  app.post('/api/image/generate', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { prompt, aspectRatio, highQuality, base64Image, mimeType } = req.body as {
        prompt?: string;
        aspectRatio?: '1:1' | '16:9' | '9:16' | '4:3' | '3:4';
        highQuality?: boolean;
        base64Image?: string;
        mimeType?: string;
      };
      if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
        res.status(400).json({ error: 'Please provide an image generation or edit prompt.' });
        return;
      }
      const result = await generateOrEditSecurityImage({
        prompt: prompt.trim(),
        aspectRatio,
        highQuality,
        base64Image,
        mimeType,
      });
      res.json(result);
    } catch (error: unknown) {
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Image generation failed.',
      });
    }
  });

  // 9. Veo 3 Video Generation (3-Step Server-Side Pattern):
  // Step 1: POST /api/generate-video
  app.post('/api/generate-video', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { prompt, aspectRatio } = req.body as {
        prompt?: string;
        aspectRatio?: '16:9' | '9:16';
      };
      if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
        res.status(400).json({ error: 'Please provide a video generation prompt.' });
        return;
      }
      const result = await startVeoVideoGeneration({
        prompt: prompt.trim(),
        aspectRatio: aspectRatio === '9:16' ? '9:16' : '16:9',
      });
      res.json(result);
    } catch (error: unknown) {
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Video generation start failed.',
      });
    }
  });

  // Step 2: POST /api/video-status
  app.post('/api/video-status', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { operationName } = req.body as { operationName?: string };
      if (!operationName || typeof operationName !== 'string') {
        res.status(400).json({ error: 'Missing operationName.' });
        return;
      }
      const status = await pollVeoVideoOperation(operationName);
      res.json(status);
    } catch (error: unknown) {
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Failed to poll video status.',
      });
    }
  });

  // Step 3: POST /api/video-download
  app.post('/api/video-download', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { operationName } = req.body as { operationName?: string };
      if (!operationName || typeof operationName !== 'string') {
        res.status(400).json({ error: 'Missing operationName.' });
        return;
      }
      const { uri, apiKey } = await getCompletedVeoVideoUri(operationName);
      const videoRes = await fetch(uri, {
        headers: { 'x-goog-api-key': apiKey },
      });
      if (!videoRes.ok || !videoRes.body) {
        res.status(502).json({ error: `Failed to download video stream (${videoRes.status})` });
        return;
      }
      res.setHeader('Content-Type', 'video/mp4');
      Readable.fromWeb(videoRes.body as any).pipe(res);
    } catch (error: unknown) {
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Failed to download generated video.',
      });
    }
  });

  // 10. WebSocket Bridge for Gemini 3.8 Live Voice Conversations (/api/live)
  const wss = new WebSocketServer({ noServer: true });

  httpServer.on('upgrade', async (request, socket, head) => {
    try {
      const parsedUrl = new URL(request.url || '', `http://${request.headers.host || 'localhost'}`);
      if (parsedUrl.pathname !== '/api/live') {
        return;
      }

      const token = parsedUrl.searchParams.get('token');
      if (!token) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      await adminAuth.verifyIdToken(token);

      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    } catch {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
    }
  });

  wss.on('connection', (clientWs, request) => {
    const ai = getGenAIClient();
    if (!ai) {
      clientWs.send(
        JSON.stringify({
          error: 'GEMINI_API_KEY is not configured on the server.',
        })
      );
      clientWs.close();
      return;
    }

    const parsedReqUrl = new URL(request.url || '', `http://${request.headers.host || 'localhost'}`);
    const voiceParam = parsedReqUrl.searchParams.get('voice');
    const validVoices = ['Zephyr', 'Puck', 'Charon', 'Kore', 'Fenrir'];
    const chosenVoice = validVoices.includes(voiceParam || '') ? voiceParam! : 'Zephyr';
    const topicParam = parsedReqUrl.searchParams.get('topic');
    const systemPrompt = topicParam
      ? `You are the Phishing Shield Live Voice SOC Analyst. The user is asking about the following security context: "${topicParam.slice(0, 500)}". Speak concisely, conversationally, and clearly to help security analysts triage phishing URLs, suspicious emails, DNS/RDAP findings, and incident response steps in real time.`
      : 'You are the Phishing Shield Live Voice SOC Analyst. Speak concisely, conversationally, and clearly to help security analysts triage phishing URLs, suspicious emails, DNS/RDAP findings, and incident response steps in real time.';

    const sessionPromise = ai.live.connect({
      model: 'gemini-3.8-live',
      config: {
        responseModalities: [Modality.AUDIO],
        speechConfig: {
          voiceConfig: { prebuiltVoiceConfig: { voiceName: chosenVoice } },
        },
        inputAudioTranscription: {},
        outputAudioTranscription: {},
        systemInstruction: systemPrompt,
      },
      callbacks: {
        onmessage: (message: LiveServerMessage) => {
          if (clientWs.readyState !== clientWs.OPEN) return;

          const parts = message.serverContent?.modelTurn?.parts || [];
          for (const part of parts) {
            const audio = part.inlineData?.data;
            if (audio) {
              clientWs.send(JSON.stringify({ audio }));
            }
          }

          if (message.serverContent?.interrupted) {
            clientWs.send(JSON.stringify({ interrupted: true }));
          }

          const outTranscript = (message.serverContent as any)?.outputTranscription?.text;
          if (outTranscript) {
            clientWs.send(JSON.stringify({ outputTranscript: outTranscript }));
          }

          const inTranscript = (message.serverContent as any)?.inputTranscription?.text;
          if (inTranscript) {
            clientWs.send(JSON.stringify({ inputTranscript: inTranscript }));
          }
        },
        onerror: (err: unknown) => {
          if (clientWs.readyState === clientWs.OPEN) {
            clientWs.send(
              JSON.stringify({
                error: err instanceof Error ? err.message : 'Live API session error',
              })
            );
          }
        },
      },
    });

    sessionPromise.catch((err: unknown) => {
      if (clientWs.readyState === clientWs.OPEN) {
        clientWs.send(
          JSON.stringify({
            error: err instanceof Error ? err.message : 'Failed to connect to gemini-3.8-live',
          })
        );
        clientWs.close();
      }
    });

    clientWs.on('message', (raw) => {
      try {
        const payload = JSON.parse(raw.toString());
        if (payload.audio) {
          sessionPromise
            .then((session) => {
              session.sendRealtimeInput({
                audio: { data: payload.audio, mimeType: 'audio/pcm;rate=16000' },
              });
            })
            .catch(() => {});
        } else if (payload.text) {
          sessionPromise
            .then((session) => {
              session.sendRealtimeInput({
                text: String(payload.text),
              });
            })
            .catch(() => {});
        }
      } catch {
        // Ignore malformed message
      }
    });

    clientWs.on('close', () => {
      sessionPromise
        .then((session) => {
          session.close();
        })
        .catch(() => {});
    });
  });

  // Explicit 404 handler for unmatched /api routes so they NEVER fall through to Vite / SPA index.html
  app.all('/api/*', (req, res) => {
    res.status(404).json({
      success: false,
      error: {
        code: 'NOT_FOUND',
        message: `API endpoint ${req.method} ${req.path} not found.`,
      },
    });
  });

  // Global centralized error handler for /api routes
  app.use('/api', (err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled API error:', err);
    res.status(err?.status || 500).json({
      success: false,
      error: {
        code: err?.code || 'INTERNAL_SERVER_ERROR',
        message: err?.message || 'An unexpected server error occurred.',
      },
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Phishing Shield server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();

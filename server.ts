import express from 'express';
import http from 'node:http';
import path from 'node:path';
import net from 'node:net';
import { Readable } from 'node:stream';
import dotenv from 'dotenv';
import multer from 'multer';
import { WebSocketServer } from 'ws';
import { createServer as createViteServer } from 'vite';
import { adminAuth, requireAuth, AuthenticatedRequest } from './src/server/firebaseAdmin.ts';
import { analyzeUrlTarget } from './src/server/urlAnalyzer.ts';
import { analyzeMessageContent } from './src/server/messageAnalyzer.ts';
import { analyzeIpAddress, classifyIpScope } from './src/server/ipAnalyzer.ts';
import { analyzeScreenshotImage } from './src/server/screenshotAnalyzer.ts';
import {
  getGenAIClient,
  Modality,
  LiveServerMessage,
  runSocMultiTurnChat,
  runSearchGroundingQuery,
  runMapsGroundingQuery,
  transcribeSecurityAudio,
  generateOrEditSecurityImage,
  startVeoVideoGeneration,
  pollVeoVideoOperation,
  getCompletedVeoVideoUri,
  generateSpeechAudio,
} from './src/server/geminiService.ts';

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

  // Live System Status endpoint for Security Engines
  app.get('/api/system-status', requireAuth, (_req: AuthenticatedRequest, res) => {
    const geminiConfigured = Boolean(
      process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY'
    );
    res.json({
      timestamp: new Date().toISOString(),
      services: [
        {
          name: 'Screenshot Upload Service',
          status: 'Operational',
          detail: 'Multipart validation (PNG/JPG/WEBP up to 10 MB) + Sharp binary header check',
        },
        {
          name: 'OCR Text Engine',
          status: 'Operational',
          detail: geminiConfigured
            ? 'Gemini 3.8 Multimodal Vision OCR + Local Tesseract.js Fallback'
            : 'Local Tesseract.js OCR Engine Active',
        },
        {
          name: 'QR Detection Engine',
          status: 'Operational',
          detail: 'Multi-pass Sharp + jsQR pixel matrix decoder',
        },
        {
          name: 'URL Security Analyzer',
          status: 'Operational',
          detail: 'Lexical, TLS X.509, Homograph, & Safe Redirect Inspector',
        },
        {
          name: 'DNS / Domain Analyzer',
          status: 'Operational',
          detail: 'Live DNS (A/AAAA/MX/TXT/SPF/DMARC) + Live RDAP Registration Lookup',
        },
        {
          name: 'Threat Intelligence',
          status: 'Operational',
          detail: 'Abuse.ch URLhaus + Spamhaus ZEN / Barracuda / SpamCop DNSBL',
        },
        {
          name: 'Gemini Explanation',
          status: geminiConfigured ? 'Operational' : 'Unavailable (Key Not Configured)',
          detail: geminiConfigured
            ? 'Gemini 3.8 Flash Evidence-Grounded SOC Analyst'
            : 'Deterministic Evidence Engine Active',
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
              error: 'Screenshot file size exceeds the 10 MB security limit.',
            });
            return;
          }
          res.status(400).json({ error: `Upload error: ${uploadErr.message}` });
          return;
        }
        res.status(400).json({
          error:
            uploadErr instanceof Error
              ? uploadErr.message
              : 'Invalid screenshot upload payload.',
        });
        return;
      }

      try {
        const file = req.file;
        if (!file || !file.buffer || file.buffer.byteLength === 0) {
          res.status(400).json({
            error: 'Please upload a valid PNG, JPG/JPEG, or WEBP screenshot image (field: "image").',
          });
          return;
        }

        const result = await analyzeScreenshotImage({
          buffer: file.buffer,
          originalName: file.originalname || 'screenshot.png',
          mimeType: file.mimetype || 'image/png',
        });

        res.json(result);
      } catch (error: unknown) {
        console.error('Screenshot scan error:', error);
        res.status(400).json({
          error:
            error instanceof Error ? error.message : 'Failed to analyze screenshot security.',
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
        res.json({ ip: cleanCandidate, source: 'Client Connection Header' });
        return;
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
      const r = await fetch('https://api.ipify.org?format=json', { signal: controller.signal });
      clearTimeout(timer);
      if (r.ok) {
        const data = await r.json();
        if (data?.ip) {
          res.json({ ip: data.ip, source: 'Network Egress Node' });
          return;
        }
      }
      res.status(404).json({ error: 'Unable to automatically determine public IP.' });
    } catch (error: unknown) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to detect public IP',
      });
    }
  });

  // 1. URL Scanner Endpoint: POST /api/scan-url
  app.post('/api/scan-url', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { url } = req.body as { url?: string };
      if (!url || typeof url !== 'string' || !url.trim()) {
        res.status(400).json({ error: 'Please provide a valid URL string to analyze.' });
        return;
      }
      if (url.length > 2048) {
        res.status(400).json({ error: 'URL exceeds maximum length of 2048 characters.' });
        return;
      }

      const result = await analyzeUrlTarget(url);
      res.json(result);
    } catch (error: unknown) {
      console.error('URL scan error:', error);
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Failed to analyze URL.',
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
        res.status(400).json({ error: 'Please provide message content to analyze.' });
        return;
      }
      if (message.length > 20000) {
        res
          .status(400)
          .json({ error: 'Message content exceeds maximum length of 20,000 characters.' });
        return;
      }

      const result = await analyzeMessageContent(message, sender, headers);
      res.json(result);
    } catch (error: unknown) {
      console.error('Message scan error:', error);
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Failed to analyze message content.',
      });
    }
  });

  // 3. Public IP Scanner Endpoint: POST /api/scan-ip
  app.post('/api/scan-ip', requireAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { ip } = req.body as { ip?: string };
      if (!ip || typeof ip !== 'string' || !ip.trim()) {
        res.status(400).json({ error: 'Please provide an IPv4 or IPv6 address to analyze.' });
        return;
      }

      const result = await analyzeIpAddress(ip.trim(), true);
      res.json(result);
    } catch (error: unknown) {
      console.error('IP scan error:', error);
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Failed to analyze IP address.',
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

  // 5. Google Search Grounding Endpoint: POST /api/grounding/search
  app.post('/api/grounding/search', requireAuth, async (req: AuthenticatedRequest, res) => {
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

  wss.on('connection', (clientWs) => {
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

    const sessionPromise = ai.live.connect({
      model: 'gemini-3.8-live',
      config: {
        responseModalities: [Modality.AUDIO],
        speechConfig: {
          voiceConfig: { prebuiltVoiceConfig: { voiceName: 'Zephyr' } },
        },
        inputAudioTranscription: {},
        outputAudioTranscription: {},
        systemInstruction:
          'You are the Phishing Shield Live Voice SOC Analyst. Speak concisely and clearly to help security analysts triage phishing URLs, suspicious emails, DNS/RDAP findings, and incident response steps in real time.',
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

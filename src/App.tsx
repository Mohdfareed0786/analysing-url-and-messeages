/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  onAuthStateChanged,
  signOut,
  sendPasswordResetEmail,
  User,
} from 'firebase/auth';
import {
  collection,
  doc,
  query,
  where,
  onSnapshot,
} from 'firebase/firestore';
import {
  Shield,
  Calendar,
  Globe,
  MessageSquareWarning,
  Network,
  History,
  FileText,
  UserCheck,
  LogOut,
  Search,
  Trash2,
  Download,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Archive,
  RefreshCw,
  Menu,
  X,
  Sparkles,
  Send,
  Volume2,
  ExternalLink,
  Maximize2,
  Radio,
  Mic,
  MicOff,
  Upload,
  Box,
  LayoutDashboard,
  QrCode,
  Image as ImageIcon,
  GraduationCap,
  BarChart3,
  Settings,
} from 'lucide-react';
import {
  auth,
  db,
  ensureUserProfile,
  updateAnalystProfile,
  saveScanRecord,
  deleteScanRecord,
  createSecurityReportFromScan,
  updateSecurityReportNotes,
  archiveSecurityReport,
  deleteSecurityReport,
  saveChatSession,
  handleFirestoreError,
  OperationType,
  UserProfileDoc,
  UserPrivateInfoDoc,
  ScanRecordDoc,
  SecurityReportDoc,
  ChatSessionDoc,
  ChatTurnItem,
  AllowedScanType,
  AllowedVerdictType,
} from './lib/firebase';
import { AuthGate } from './components/AuthGate';
import { ScanResultView } from './components/ScanResultView';
import { AiSecuritySuite } from './components/AiSecuritySuite';
import { ScanHistoryHeatmap, type RiskCategoryFilter } from './components/ScanHistoryHeatmap';
import { ScanRiskTrendsChart } from './components/ScanRiskTrendsChart';
import { LiveVoiceAssistant } from './components/LiveVoiceAssistant';
import { CyberMatrix3D } from './components/CyberMatrix3D';
import { DashboardOverview } from './components/DashboardOverview';
import { ScreenshotScannerWorkspace } from './components/ScreenshotScannerWorkspace';
import { QrScannerWorkspace } from './components/QrScannerWorkspace';
import { DomainIntelWorkspace } from './components/DomainIntelWorkspace';
import { SecurityAwarenessWorkspace } from './components/SecurityAwarenessWorkspace';
import { SecurityAnalyticsWorkspace } from './components/SecurityAnalyticsWorkspace';
import { SecuritySettingsWorkspace } from './components/SecuritySettingsWorkspace';

type ActiveSection =
  | 'dashboard-overview'
  | 'url-scanner'
  | 'message-scanner'
  | 'screenshot-scanner'
  | 'qr-scanner'
  | 'ip-scanner'
  | 'domain-intel'
  | 'scan-history'
  | 'security-reports'
  | 'security-awareness'
  | 'security-analytics'
  | 'ai-assistant'
  | 'cyber-matrix-3d'
  | 'live-voice'
  | 'user-profile'
  | 'security-settings';

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [activeSection, setActiveSection] = useState<ActiveSection>('dashboard-overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Firestore real-time state
  const [profile, setProfile] = useState<UserProfileDoc | null>(null);
  const [privateInfo, setPrivateInfo] = useState<UserPrivateInfoDoc | null>(null);
  const [scans, setScans] = useState<ScanRecordDoc[]>([]);
  const [reports, setReports] = useState<SecurityReportDoc[]>([]);
  const [chatSessions, setChatSessions] = useState<ChatSessionDoc[]>([]);
  const [dataLoading, setDataLoading] = useState(true);

  // URL Scanner State
  const [urlInput, setUrlInput] = useState('');
  const [urlScanning, setUrlScanning] = useState(false);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [urlResult, setUrlResult] = useState<{
    scanId: string | null;
    target: string;
    data: Record<string, any>;
  } | null>(null);

  // Message Scanner State
  const [msgInput, setMsgInput] = useState('');
  const [msgSender, setMsgSender] = useState('');
  const [msgHeaders, setMsgHeaders] = useState('');
  const [msgScanning, setMsgScanning] = useState(false);
  const [msgError, setMsgError] = useState<string | null>(null);
  const [msgResult, setMsgResult] = useState<{
    scanId: string | null;
    target: string;
    data: Record<string, any>;
  } | null>(null);
  const [msgAudioRecording, setMsgAudioRecording] = useState(false);
  const [msgTranscribing, setMsgTranscribing] = useState(false);
  const msgMediaRecorderRef = useRef<MediaRecorder | null>(null);
  const msgAudioChunksRef = useRef<Blob[]>([]);

  // IP Scanner State
  const [ipInput, setIpInput] = useState('');
  const [ipScanning, setIpScanning] = useState(false);
  const [ipError, setIpError] = useState<string | null>(null);
  const [ipResult, setIpResult] = useState<{
    scanId: string | null;
    target: string;
    data: Record<string, any>;
  } | null>(null);

  // History Inspection & Filter State
  const [historyFilter, setHistoryFilter] = useState<'all' | 'url' | 'message' | 'ip'>('all');
  const [historySearch, setHistorySearch] = useState('');
  const [historyDateFilter, setHistoryDateFilter] = useState<string | null>(null);
  const [historyRiskCategory, setHistoryRiskCategory] = useState<RiskCategoryFilter>('all');
  const [selectedHistoryScan, setSelectedHistoryScan] = useState<ScanRecordDoc | null>(null);

  // Reports State
  const [reportFilter, setReportFilter] = useState<'all' | 'active' | 'archived'>('all');
  const [selectedReport, setSelectedReport] = useState<SecurityReportDoc | null>(null);
  const [editReportTitle, setEditReportTitle] = useState('');
  const [editReportNotes, setEditReportNotes] = useState('');
  const [savingReportEdit, setSavingReportEdit] = useState(false);
  const [reportFeedback, setReportFeedback] = useState<string | null>(null);

  // Profile Form State
  const [profileName, setProfileName] = useState('');
  const [profileOrg, setProfileOrg] = useState('');
  const [profileJob, setProfileJob] = useState('');
  const [savingProfile, setSavingProfile] = useState(false);
  const [profileFeedback, setProfileFeedback] = useState<string | null>(null);

  // Dedicated AI Suite Initial Prompt (when jumping to full AI Studio)
  const [suiteInitialPrompt, setSuiteInitialPrompt] = useState<string | null>(null);

  // Gemini Live Voice Quick Triage Modal State
  const [voiceModalOpen, setVoiceModalOpen] = useState(true);
  const [voiceInitialTopic, setVoiceInitialTopic] = useState<string | null>(null);

  // Slide-Over Quick Gemini AI Assistant Drawer State
  const [copilotDrawerOpen, setCopilotDrawerOpen] = useState(false);
  const [drawerMessages, setDrawerMessages] = useState<ChatTurnItem[]>([]);
  const [drawerInput, setDrawerInput] = useState('');
  const [drawerSending, setDrawerSending] = useState(false);
  const [drawerError, setDrawerError] = useState<string | null>(null);
  const [drawerChatId, setDrawerChatId] = useState<string | undefined>(undefined);
  const [drawerModel, setDrawerModel] = useState<
    'gemini-3.1-flash-lite' | 'gemini-3.8-flash' | 'gemini-4-argon' | 'gemini-3.1-pro-preview'
  >('gemini-3.8-flash');
  const [drawerTtsIdx, setDrawerTtsIdx] = useState<number | null>(null);
  const drawerScrollRef = useRef<HTMLDivElement | null>(null);
  const drawerAudioRef = useRef<HTMLAudioElement | null>(null);

  useEffect(() => {
    if (drawerScrollRef.current) {
      drawerScrollRef.current.scrollTop = drawerScrollRef.current.scrollHeight;
    }
  }, [drawerMessages, drawerSending, copilotDrawerOpen]);

  // 1. Auth Lifecycle
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      setAuthReady(true);
      if (currentUser) {
        try {
          await ensureUserProfile(currentUser);
        } catch (err) {
          console.error('Failed to sync initial user profile:', err);
        }
      } else {
        setProfile(null);
        setPrivateInfo(null);
        setScans([]);
        setReports([]);
        setChatSessions([]);
      }
    });
    return () => unsubscribe();
  }, []);

  // 2. Real-time Firestore Subscriptions (Strictly scoped to authenticated user UID)
  useEffect(() => {
    if (!authReady || !user) return;

    setDataLoading(true);
    const uid = user.uid;

    const userDocRef = doc(db, 'users', uid);
    const unsubProfile = onSnapshot(
      userDocRef,
      (snap) => {
        if (snap.exists()) {
          const data = snap.data() as UserProfileDoc;
          setProfile(data);
          setProfileName(data.displayName || '');
          setProfileOrg(data.organization || '');
          setProfileJob(data.jobTitle || '');
        }
      },
      (err) => handleFirestoreError(err, OperationType.GET, `users/${uid}`)
    );

    const privateDocRef = doc(db, 'users', uid, 'private', 'info');
    const unsubPrivate = onSnapshot(
      privateDocRef,
      (snap) => {
        if (snap.exists()) {
          setPrivateInfo(snap.data() as UserPrivateInfoDoc);
        }
      },
      (err) => handleFirestoreError(err, OperationType.GET, `users/${uid}/private/info`)
    );

    const scansQuery = query(collection(db, 'scans'), where('userId', '==', uid));
    const unsubScans = onSnapshot(
      scansQuery,
      (snap) => {
        const list = snap.docs.map((d) => d.data() as ScanRecordDoc);
        list.sort((a, b) => {
          const tA = a.createdAt?.toMillis?.() || 0;
          const tB = b.createdAt?.toMillis?.() || 0;
          return tB - tA;
        });
        setScans(list);
        setDataLoading(false);
      },
      (err) => handleFirestoreError(err, OperationType.LIST, 'scans')
    );

    const reportsQuery = query(collection(db, 'reports'), where('userId', '==', uid));
    const unsubReports = onSnapshot(
      reportsQuery,
      (snap) => {
        const list = snap.docs.map((d) => d.data() as SecurityReportDoc);
        list.sort((a, b) => {
          const tA = a.createdAt?.toMillis?.() || 0;
          const tB = b.createdAt?.toMillis?.() || 0;
          return tB - tA;
        });
        setReports(list);
      },
      (err) => handleFirestoreError(err, OperationType.LIST, 'reports')
    );

    const chatsQuery = query(collection(db, 'chats'), where('userId', '==', uid));
    const unsubChats = onSnapshot(
      chatsQuery,
      (snap) => {
        const list = snap.docs.map((d) => d.data() as ChatSessionDoc);
        list.sort((a, b) => {
          const tA = a.updatedAt?.toMillis?.() || 0;
          const tB = b.updatedAt?.toMillis?.() || 0;
          return tB - tA;
        });
        setChatSessions(list);
      },
      (err) => handleFirestoreError(err, OperationType.LIST, 'chats')
    );

    return () => {
      unsubProfile();
      unsubPrivate();
      unsubScans();
      unsubReports();
      unsubChats();
    };
  }, [authReady, user]);

  // Authenticated Fetch Helper with Safe Content-Type & Error Handling
  const authenticatedFetch = async (endpoint: string, options: RequestInit = {}) => {
    if (!user) throw new Error('User is not authenticated.');
    const token = await user.getIdToken();

    let res: Response;
    try {
      res = await fetch(endpoint, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          ...(options.headers || {}),
        },
      });
    } catch (fetchErr: unknown) {
      console.error(`Network fetch failed for ${endpoint}:`, fetchErr);
      throw new Error(
        'Failed to connect to the backend server. Please verify network connectivity.'
      );
    }

    const contentType = res.headers.get('content-type') || '';
    const isJson = contentType.toLowerCase().includes('application/json');

    if (!res.ok) {
      if (isJson) {
        let errorData: any = null;
        try {
          errorData = await res.json();
        } catch (jsonErr) {
          console.error(`Failed to parse error JSON from ${endpoint}:`, jsonErr);
        }
        const errorMsg =
          typeof errorData?.error === 'string'
            ? errorData.error
            : errorData?.error?.message ||
              errorData?.message ||
              `Request failed with HTTP status ${res.status}`;
        throw new Error(errorMsg);
      } else {
        // Unexpected non-JSON (e.g., HTML 502/504 error page from reverse proxy or 404 HTML fallback)
        const rawBody = await res.text().catch(() => '');
        console.error(
          `Unexpected non-JSON response from ${endpoint} (HTTP ${res.status}, Content-Type: ${contentType}):`,
          rawBody.slice(0, 500)
        );
        throw new Error(
          'The analysis service returned an unexpected response.\nPlease check the API endpoint and backend logs.'
        );
      }
    }

    if (!isJson) {
      const rawBody = await res.text().catch(() => '');
      console.error(
        `Expected JSON but received non-JSON from ${endpoint} (HTTP ${res.status}, Content-Type: ${contentType}):`,
        rawBody.slice(0, 500)
      );
      throw new Error(
        'The analysis service returned an unexpected response.\nPlease check the API endpoint and backend logs.'
      );
    }

    try {
      return await res.json();
    } catch (parseErr: unknown) {
      console.error(`Failed to parse successful JSON response from ${endpoint}:`, parseErr);
      throw new Error(
        'The analysis service returned an unexpected response.\nPlease check the API endpoint and backend logs.'
      );
    }
  };

  // Active scan context for the Slide-Over Gemini Copilot Drawer
  const activeWorkspaceScanContext = useMemo(() => {
    if (activeSection === 'url-scanner' && urlResult) {
      return {
        label: `URL Scan: ${urlResult.target}`,
        json: JSON.stringify(urlResult.data, null, 2),
      };
    }
    if (activeSection === 'message-scanner' && msgResult) {
      return {
        label: `Message Scan: ${msgResult.target.slice(0, 48)}`,
        json: JSON.stringify(msgResult.data, null, 2),
      };
    }
    if (activeSection === 'ip-scanner' && ipResult) {
      return {
        label: `Public IP Scan: ${ipResult.target}`,
        json: JSON.stringify(ipResult.data, null, 2),
      };
    }
    if (activeSection === 'scan-history' && selectedHistoryScan) {
      return {
        label: `History Scan: ${selectedHistoryScan.target.slice(0, 48)}`,
        json: JSON.stringify(selectedHistoryScan.analysisData, null, 2),
      };
    }
    return null;
  }, [activeSection, urlResult, msgResult, ipResult, selectedHistoryScan]);

  // Handler: Send Message in Quick Gemini Copilot Drawer
  const handleSendDrawerMessage = async (e?: React.FormEvent, overridePrompt?: string) => {
    if (e) e.preventDefault();
    const text = (overridePrompt ?? drawerInput).trim();
    if (!text || drawerSending || !user) return;
    if (!overridePrompt) setDrawerInput('');

    setDrawerError(null);
    const userTurn: ChatTurnItem = {
      role: 'user',
      text,
      timestamp: new Date().toISOString(),
    };
    const nextHistory = [...drawerMessages, userTurn];
    setDrawerMessages(nextHistory);
    setDrawerSending(true);

    try {
      const data = await authenticatedFetch('/api/chat', {
        method: 'POST',
        body: JSON.stringify({
          model: drawerModel,
          rolePersona: 'soc-analyst',
          history: drawerMessages.map((m) => ({ role: m.role, text: m.text })),
          message: text,
          useSearchGrounding: false,
          enableSecurityTools: true,
          attachedScanContext: activeWorkspaceScanContext?.json,
        }),
      });

      const modelTurn: ChatTurnItem = {
        role: 'model',
        text: data.reply || 'Analysis complete.',
        timestamp: new Date().toISOString(),
        sources: Array.isArray(data.webSources) ? data.webSources : undefined,
        executedTools: Array.isArray(data.executedTools) ? data.executedTools : undefined,
      };

      const updated = [...nextHistory, modelTurn];
      setDrawerMessages(updated);

      // Non-blocking Firestore persistence
      try {
        const savedId = await saveChatSession({
          chatId: drawerChatId,
          userId: user.uid,
          title: updated[0]?.text.slice(0, 60) || 'Gemini Copilot Session',
          rolePersona: 'soc-analyst',
          modelName: data.modelUsed || drawerModel,
          messages: updated,
        });
        setDrawerChatId(savedId);
      } catch (persistErr) {
        console.warn('Non-fatal drawer chat persistence warning:', persistErr);
      }
    } catch (err: unknown) {
      setDrawerError(err instanceof Error ? err.message : 'Gemini Assistant request failed.');
    } finally {
      setDrawerSending(false);
    }
  };

  const handlePlayDrawerTts = async (text: string, idx: number) => {
    if (drawerTtsIdx === idx) {
      if (drawerAudioRef.current) {
        drawerAudioRef.current.pause();
        drawerAudioRef.current = null;
      }
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        window.speechSynthesis.cancel();
      }
      setDrawerTtsIdx(null);
      return;
    }
    if (drawerAudioRef.current) {
      drawerAudioRef.current.pause();
      drawerAudioRef.current = null;
    }
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
    setDrawerTtsIdx(idx);
    try {
      const res = await authenticatedFetch('/api/tts', {
        method: 'POST',
        body: JSON.stringify({ text: text.slice(0, 1400), voiceName: 'Kore' }),
      });
      if (res.audioDataUrl) {
        const audio = new Audio(res.audioDataUrl);
        drawerAudioRef.current = audio;
        audio.onended = () => {
          setDrawerTtsIdx(null);
          drawerAudioRef.current = null;
        };
        await audio.play();
      } else {
        setDrawerTtsIdx(null);
      }
    } catch {
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        const utterance = new SpeechSynthesisUtterance(
          text.replace(/[*#`_~]/g, '').slice(0, 1200)
        );
        utterance.onend = () => setDrawerTtsIdx(null);
        utterance.onerror = () => setDrawerTtsIdx(null);
        window.speechSynthesis.speak(utterance);
      } else {
        setDrawerTtsIdx(null);
      }
    }
  };

  // Handler: Trigger Gemini Assistant from any ScanResultView
  const handleAskGeminiAboutScan = (contextPrompt: string) => {
    setCopilotDrawerOpen(true);
    handleSendDrawerMessage(undefined, contextPrompt);
  };

  // Handler: Execute URL Scan
  const handleRunUrlScan = async (e?: React.FormEvent, overrideUrl?: string) => {
    if (e) e.preventDefault();
    const targetUrl = (overrideUrl ?? urlInput).trim();
    if (!targetUrl || !user) return;
    if (overrideUrl) setUrlInput(overrideUrl);

    setUrlScanning(true);
    setUrlError(null);
    try {
      const data = await authenticatedFetch('/api/scan-url', {
        method: 'POST',
        body: JSON.stringify({ url: targetUrl }),
      });

      const summaryText =
        data.aiExplanation?.executiveSummary ||
        `URL ${data.url} analyzed. Risk Score: ${data.riskScore}/100 (${data.verdict}). Domain Age: ${data.domainAnalysis?.rdap?.formattedAge || 'Unavailable'}.`;

      const scanId = await saveScanRecord({
        userId: user.uid,
        scanType: 'url',
        target: data.url || targetUrl,
        riskScore: data.riskScore,
        verdict: data.verdict,
        summary: summaryText,
        analysisData: data,
      });

      setUrlResult({ scanId, target: data.url || targetUrl, data });
    } catch (err: unknown) {
      setUrlError(err instanceof Error ? err.message : 'URL scan failed.');
    } finally {
      setUrlScanning(false);
    }
  };

  // Audio Transcription Handlers for Message Scanner (gemini-3.5-transcribe)
  const handleStartMessageAudioRecord = async () => {
    setMsgError(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      msgAudioChunksRef.current = [];
      const recorder = new MediaRecorder(stream);
      msgMediaRecorderRef.current = recorder;

      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) msgAudioChunksRef.current.push(e.data);
      };

      recorder.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(msgAudioChunksRef.current, {
          type: recorder.mimeType || 'audio/webm',
        });
        await handleTranscribeMessageBlob(blob, recorder.mimeType || 'audio/webm');
      };

      recorder.start();
      setMsgAudioRecording(true);
    } catch (err: unknown) {
      setMsgError(
        err instanceof Error ? err.message : 'Unable to access microphone for recording.'
      );
    }
  };

  const handleStopMessageAudioRecord = () => {
    if (msgMediaRecorderRef.current && msgAudioRecording) {
      msgMediaRecorderRef.current.stop();
      setMsgAudioRecording(false);
    }
  };

  const handleTranscribeMessageBlob = async (blob: Blob, mimeType: string) => {
    setMsgTranscribing(true);
    setMsgError(null);
    try {
      const reader = new FileReader();
      const base64Promise = new Promise<string>((resolve, reject) => {
        reader.onloadend = () => resolve(String(reader.result || ''));
        reader.onerror = reject;
      });
      reader.readAsDataURL(blob);
      const base64Data = await base64Promise;

      const res = await authenticatedFetch('/api/transcribe', {
        method: 'POST',
        body: JSON.stringify({
          audioBase64: base64Data,
          mimeType,
          customPrompt:
            'Transcribe this suspicious voicemail or voice note for cybersecurity and phishing analysis. Preserve all URLs, phone numbers, and urgent requests.',
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error?.message || data.error || 'Transcription failed.');
      }
      if (data.transcript) {
        setMsgInput((prev) => (prev ? `${prev}\n\n${data.transcript}` : data.transcript));
      }
    } catch (err: unknown) {
      setMsgError(
        err instanceof Error ? err.message : 'Audio transcription with gemini-3.5-transcribe failed.'
      );
    } finally {
      setMsgTranscribing(false);
    }
  };

  const handleMessageAudioFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    await handleTranscribeMessageBlob(file, file.type || 'audio/webm');
    e.target.value = '';
  };

  // Handler: Execute Message Scan
  const handleRunMessageScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!msgInput.trim() || !user) return;

    setMsgScanning(true);
    setMsgError(null);
    try {
      const data = await authenticatedFetch('/api/scan-message', {
        method: 'POST',
        body: JSON.stringify({
          message: msgInput.trim(),
          sender: msgSender.trim() || undefined,
          headers: msgHeaders.trim() || undefined,
        }),
      });

      const excerpt =
        msgInput.trim().length > 120
          ? `${msgInput.trim().slice(0, 120)}...`
          : msgInput.trim();

      const summaryText =
        data.aiExplanation?.executiveSummary ||
        `Message analyzed (${data.mlClassification?.primaryIntent}). Risk Score: ${data.riskScore}/100 (${data.verdict}).`;

      const scanId = await saveScanRecord({
        userId: user.uid,
        scanType: 'message',
        target: excerpt,
        riskScore: data.riskScore,
        verdict: data.verdict,
        summary: summaryText,
        analysisData: data,
      });

      setMsgResult({ scanId, target: excerpt, data });
    } catch (err: unknown) {
      setMsgError(err instanceof Error ? err.message : 'Message scan failed.');
    } finally {
      setMsgScanning(false);
    }
  };

  // Handler: Execute Public IP Scan
  const handleRunIpScan = async (e?: React.FormEvent, overrideIp?: string) => {
    if (e) e.preventDefault();
    const targetIp = (overrideIp ?? ipInput).trim();
    if (!targetIp || !user) return;
    if (overrideIp) setIpInput(overrideIp);

    setIpScanning(true);
    setIpError(null);
    try {
      const data = await authenticatedFetch('/api/scan-ip', {
        method: 'POST',
        body: JSON.stringify({ ip: targetIp }),
      });

      const summaryText =
        data.aiExplanation?.executiveSummary ||
        `IP ${data.ip} (${data.asn}, ${data.organization}) analyzed. Risk Score: ${data.riskScore}/100 (${data.verdict}).`;

      const scanId = await saveScanRecord({
        userId: user.uid,
        scanType: 'ip',
        target: data.ip || targetIp,
        riskScore: data.riskScore,
        verdict: data.verdict,
        summary: summaryText,
        analysisData: data,
      });

      setIpResult({ scanId, target: data.ip || targetIp, data });
    } catch (err: unknown) {
      setIpError(err instanceof Error ? err.message : 'IP scan failed.');
    } finally {
      setIpScanning(false);
    }
  };

  // Handler: Detect & Scan My Public IP
  const handleDetectAndScanMyIp = async () => {
    setIpScanning(true);
    setIpError(null);
    try {
      const myIpData = await authenticatedFetch('/api/my-ip');
      if (myIpData?.ip) {
        setIpInput(myIpData.ip);
        await handleRunIpScan(undefined, myIpData.ip);
      }
    } catch (err: unknown) {
      setIpError(err instanceof Error ? err.message : 'Could not detect public IP.');
      setIpScanning(false);
    }
  };

  // Handler: Create Security Report from Scan
  const handleCreateReport = async (params: {
    scanId: string;
    scanType: AllowedScanType;
    target: string;
    riskScore: number;
    verdict: AllowedVerdictType;
    defaultNotes: string;
  }) => {
    if (!user) return;
    await createSecurityReportFromScan({
      userId: user.uid,
      scanId: params.scanId,
      title: `${params.scanType.toUpperCase()} Threat Assessment — ${params.target.slice(0, 60)}`,
      scanType: params.scanType,
      target: params.target,
      riskScore: params.riskScore,
      verdict: params.verdict,
      analystNotes: params.defaultNotes,
    });
  };

  // Filtered Scan History
  const filteredScans = useMemo(() => {
    return scans.filter((s) => {
      if (historyFilter !== 'all' && s.scanType !== historyFilter) return false;
      if (historyDateFilter) {
        let scanDateStr = '';
        if (s.createdAt?.toDate) {
          scanDateStr = s.createdAt.toDate().toISOString().slice(0, 10);
        } else if (s.createdAt) {
          scanDateStr = new Date(s.createdAt as any).toISOString().slice(0, 10);
        }
        if (scanDateStr !== historyDateFilter) return false;
      }
      if (historyRiskCategory !== 'all') {
        if (historyRiskCategory === 'high' && s.riskScore < 50) return false;
        if (historyRiskCategory === 'medium' && (s.riskScore < 25 || s.riskScore >= 50)) return false;
        if (historyRiskCategory === 'low' && s.riskScore >= 25) return false;
      }
      if (historySearch.trim()) {
        const q = historySearch.toLowerCase();
        return (
          s.target.toLowerCase().includes(q) ||
          s.verdict.toLowerCase().includes(q) ||
          s.summary.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [scans, historyFilter, historySearch, historyDateFilter, historyRiskCategory]);

  // Filtered Security Reports
  const filteredReports = useMemo(() => {
    return reports.filter((r) => {
      if (reportFilter !== 'all' && r.status !== reportFilter) return false;
      return true;
    });
  }, [reports, reportFilter]);

  // Export Scan History CSV
  const handleExportHistoryCsv = () => {
    if (scans.length === 0) return;
    const headers = ['Scan ID', 'Type', 'Target', 'Risk Score', 'Verdict', 'Timestamp'];
    const rows = scans.map((s) => [
      s.scanId,
      s.scanType.toUpperCase(),
      `"${s.target.replace(/"/g, '""')}"`,
      String(s.riskScore),
      s.verdict,
      s.createdAt?.toDate ? s.createdAt.toDate().toISOString() : '',
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `phishing-shield-scans-${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Export Report as Markdown
  const handleDownloadReportMarkdown = (rep: SecurityReportDoc) => {
    const md = `# ${rep.title}
- **Report ID**: ${rep.reportId}
- **Associated Scan ID**: ${rep.scanId}
- **Scan Vector**: ${rep.scanType.toUpperCase()}
- **Inspected Target**: ${rep.target}
- **Evidence Risk Score**: ${rep.riskScore} / 100
- **Verdict**: ${rep.verdict}
- **Report Status**: ${rep.status.toUpperCase()}
- **Generated By**: ${profile?.displayName || user?.email || 'Analyst'} (${profile?.organization || 'SOC'})

---

## Analyst Assessment & Remediation Notes

${rep.analystNotes || 'No additional analyst notes recorded.'}
`;
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${rep.reportId}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    setSavingProfile(true);
    setProfileFeedback(null);
    try {
      await updateAnalystProfile(user.uid, {
        displayName: profileName,
        organization: profileOrg,
        jobTitle: profileJob,
      });
      setProfileFeedback('Analyst profile updated in Firestore.');
    } catch (err: unknown) {
      setProfileFeedback(err instanceof Error ? err.message : 'Failed to update profile.');
    } finally {
      setSavingProfile(false);
    }
  };

  const handlePasswordResetRequest = async () => {
    if (!user?.email) {
      setProfileFeedback('No email address is linked to this authentication session.');
      return;
    }
    try {
      await sendPasswordResetEmail(auth, user.email);
      setProfileFeedback(`Password reset email dispatched to ${user.email}.`);
    } catch (err: unknown) {
      setProfileFeedback(err instanceof Error ? err.message : 'Could not send reset email.');
    }
  };

  if (!authReady) {
    return (
      <div className="min-h-screen bg-[#030712] text-slate-300 flex items-center justify-center font-mono text-sm">
        Initializing Phishing Shield Security Session...
      </div>
    );
  }

  if (!user) {
    return <AuthGate />;
  }

  const navItems: { id: ActiveSection; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: 'dashboard-overview', label: 'Dashboard Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'url-scanner', label: 'Scan URL', icon: <Globe className="w-4 h-4" /> },
    { id: 'message-scanner', label: 'Scan Message', icon: <MessageSquareWarning className="w-4 h-4" /> },
    { id: 'screenshot-scanner', label: 'Scan Screenshot', icon: <ImageIcon className="w-4 h-4" /> },
    { id: 'qr-scanner', label: 'Scan QR Code', icon: <QrCode className="w-4 h-4" /> },
    { id: 'ip-scanner', label: 'Scan Public IP', icon: <Network className="w-4 h-4" /> },
    { id: 'domain-intel', label: 'Domain Intelligence', icon: <Globe className="w-4 h-4 text-sky-600" /> },
    {
      id: 'scan-history',
      label: 'Scan History',
      icon: <History className="w-4 h-4" />,
      count: scans.length,
    },
    {
      id: 'security-reports',
      label: 'Security Reports',
      icon: <FileText className="w-4 h-4" />,
      count: reports.length,
    },
    { id: 'security-awareness', label: 'Security Awareness', icon: <GraduationCap className="w-4 h-4" /> },
    { id: 'security-analytics', label: 'Security Analytics', icon: <BarChart3 className="w-4 h-4" /> },
    {
      id: 'ai-assistant',
      label: 'AI Security Assistant',
      icon: <Sparkles className="w-4 h-4 text-emerald-600" />,
      count: chatSessions.length,
    },
    {
      id: 'cyber-matrix-3d',
      label: '3D Threat Matrix',
      icon: <Box className="w-4 h-4 text-indigo-600" />,
    },
    {
      id: 'live-voice',
      label: 'Live Voice Copilot',
      icon: <Radio className="w-4 h-4 text-emerald-600" />,
    },
    { id: 'user-profile', label: 'Profile', icon: <UserCheck className="w-4 h-4" /> },
    { id: 'security-settings', label: 'Security Settings', icon: <Settings className="w-4 h-4" /> },
  ];

  const sectionTitleMap: Record<ActiveSection, string> = {
    'dashboard-overview': 'SOC Command & Threat Overview',
    'url-scanner': 'URL, Domain, DNS & RDAP Scanner',
    'message-scanner': 'Message, Email & SMS NLP Scanner',
    'screenshot-scanner': 'Screenshot OCR & Vision Phishing Inspector',
    'qr-scanner': 'QR Code Quishing & Payload Decoder',
    'ip-scanner': 'Public IP Reputation & DNSBL Scanner',
    'domain-intel': 'Domain Intelligence & Authoritative RDAP Registry',
    'scan-history': 'Authenticated Threat Scan Vault',
    'security-reports': 'Incident & Security Reports',
    'security-awareness': 'Security Awareness & Anti-Scam Training',
    'security-analytics': 'Empirical Threat Telemetry & Risk Analytics',
    'ai-assistant': 'Gemini AI Security Assistant & Multi-Modal SOC Studio',
    'cyber-matrix-3d': '3D Cyber Defense Aegis Matrix & Spatial Threat Radar',
    'live-voice': 'Gemini 3.8 Live Voice Security Copilot',
    'user-profile': 'Analyst Profile & Session Security',
    'security-settings': 'System Health, 12-Subsystem Status & Settings',
  };

  const highRiskCount = scans.filter((s) => s.riskScore >= 50).length;

  return (
    <div className="min-h-screen bg-[#030712] text-slate-100 flex">
      {/* Sidebar Navigation (264px Desktop) */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-[264px] bg-[#070d19] border-r border-slate-800 flex flex-col transition-transform duration-200 lg:static lg:translate-x-0 ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="px-6 py-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Shield className="w-5 h-5 text-emerald-400 shrink-0" />
            <span className="text-base font-bold tracking-tight text-white font-display">
              Phishing Shield
            </span>
          </div>
          <button
            type="button"
            onClick={() => setMobileMenuOpen(false)}
            className="lg:hidden text-slate-400 hover:text-white cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-2.5 border-b border-slate-800 text-[11px] font-mono text-slate-400 tracking-wide">
          Detect. Analyze. Protect.
        </div>

        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const active = activeSection === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  setActiveSection(item.id);
                  setMobileMenuOpen(false);
                }}
                className={`w-full flex items-center justify-between px-3.5 py-2 rounded-md text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                  active
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                <span className="flex items-center gap-3">
                  {item.icon}
                  <span>{item.label}</span>
                </span>
                {typeof item.count === 'number' && (
                  <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                    {item.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Analyst Session Summary & Logout */}
        <div className="p-4 border-t border-slate-800 space-y-3 bg-[#050914]">
          <div className="text-xs space-y-0.5">
            <p className="font-semibold text-white truncate">
              {profile?.displayName || user.displayName || 'Security Analyst'}
            </p>
            <p className="text-slate-400 font-mono text-[11px] truncate">
              {privateInfo?.email || user.email || user.phoneNumber || user.uid.slice(0, 12)}
            </p>
          </div>
          <button
            type="button"
            onClick={() => signOut(auth)}
            className="w-full py-2 px-3 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-md transition-colors flex items-center justify-center gap-2 cursor-pointer whitespace-nowrap"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out Session</span>
          </button>
        </div>
      </aside>

      {/* Main Content Viewport */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar Contract: Breadcrumb Trail on Left, Summary Metrics & Actions on Right */}
        <header className="px-6 lg:px-8 py-3.5 border-b border-slate-800 bg-[#070d19]/90 backdrop-blur-md sticky top-0 z-20 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden text-slate-400 hover:text-white cursor-pointer"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2 text-xs sm:text-sm text-slate-400 truncate">
              <span className="font-medium text-slate-500">Workspace</span>
              <span aria-hidden="true">/</span>
              <span className="font-semibold text-white truncate">
                {sectionTitleMap[activeSection]}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4 shrink-0 text-xs">
            <div className="hidden md:flex items-center gap-3 text-slate-400 font-mono tabular-nums">
              <span>Scans: {scans.length}</span>
              <span aria-hidden="true" className="text-slate-700">·</span>
              <span className="text-red-400">High Risk: {highRiskCount}</span>
              <span aria-hidden="true" className="text-slate-700">·</span>
              <span className="text-indigo-400">Reports: {reports.length}</span>
            </div>

            {scans.length > 0 && (
              <button
                type="button"
                onClick={handleExportHistoryCsv}
                className="hidden sm:flex px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-md transition-colors items-center gap-1.5 whitespace-nowrap cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-slate-400" />
                <span>Export CSV</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => setActiveSection('cyber-matrix-3d')}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer shadow-2xs ${
                activeSection === 'cyber-matrix-3d'
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700'
              }`}
              title="Launch 3D Cyber Threat Matrix (Three.js PBR)"
            >
              <Box className="w-3.5 h-3.5 text-blue-400" />
              <span>3D Matrix</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setVoiceInitialTopic(null);
                setVoiceModalOpen(true);
              }}
              className="px-3.5 py-1.5 text-xs font-semibold text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer shadow-2xs"
              title="Launch hands-free real-time conversation with Gemini 3.8 Live"
            >
              <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
              <span>Live Voice</span>
            </button>

            <button
              type="button"
              onClick={() => setCopilotDrawerOpen(true)}
              className="px-3.5 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer shadow-sm"
            >
              <Sparkles className="w-3.5 h-3.5 text-blue-200" />
              <span>Gemini AI Assistant</span>
            </button>
          </div>
        </header>

        {/* Active Workspace Body */}
        <main className="flex-1 max-w-[1320px] w-full mx-auto px-6 lg:px-8 py-8 space-y-8">
          {/* ================================================================= */}
          {/* 0. DASHBOARD OVERVIEW WORKSPACE                                   */}
          {/* ================================================================= */}
          {activeSection === 'dashboard-overview' && (
            <DashboardOverview
              scans={scans}
              reportsCount={reports.length}
              onNavigate={(sec) => setActiveSection(sec)}
              onSelectScan={(scan) => setSelectedHistoryScan(scan)}
              onLaunchVoice={() => setVoiceModalOpen(true)}
            />
          )}

          {/* ================================================================= */}
          {/* 1. URL & DOMAIN SCANNER WORKSPACE                                 */}
          {/* ================================================================= */}
          {activeSection === 'url-scanner' && (
            <div className="space-y-8">
              <div className="bg-[#0b1325] border border-slate-800/80 rounded-xl p-6 space-y-5 shadow-sm">
                <div className="space-y-1">
                  <h2 className="text-xl font-bold text-white font-display">
                    Live URL, Domain, DNS & RDAP Inspection
                  </h2>
                  <p className="text-xs text-slate-400">
                    Analyzes URL syntax, IDN homographs, live DNS records (A/AAAA/MX/NS/SPF/DMARC),
                    authoritative RDAP domain registration age, TLS X.509 certificates, HTTP
                    redirects, and resolved Public IP DNSBL reputation.
                  </p>
                </div>

                <form onSubmit={(e) => handleRunUrlScan(e)} className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1 relative">
                    <Globe className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                    <input
                      type="text"
                      required
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="Enter URL to inspect (e.g., https://example.com/login)"
                      className="w-full pl-10 pr-4 py-2.5 text-sm font-mono bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={urlScanning}
                    className="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-sm rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap cursor-pointer shadow-sm"
                  >
                    <Search className="w-4 h-4" />
                    <span>{urlScanning ? 'Running Live Telemetry...' : 'Analyze URL'}</span>
                  </button>
                </form>

                {/* Quick Real-World Target Presets */}
                <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                  <span className="text-slate-400">Quick Live Targets:</span>
                  {[
                    { label: 'google.com (Established HTTPS)', url: 'https://www.google.com' },
                    { label: 'github.com (SPF/DMARC + TLS)', url: 'https://github.com/login' },
                    { label: 'neverssl.com (Cleartext HTTP)', url: 'http://neverssl.com' },
                    {
                      label: 'Suspicious Brand-Lure Pattern',
                      url: 'http://secure-paypal-account-verify.login-update.top/signin?session=token8912',
                    },
                  ].map((preset) => (
                    <button
                      key={preset.url}
                      type="button"
                      disabled={urlScanning}
                      onClick={() => handleRunUrlScan(undefined, preset.url)}
                      className="px-2.5 py-1 bg-slate-900/90 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded text-[11px] font-mono transition-colors cursor-pointer whitespace-nowrap"
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>

                {urlError && (
                  <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400 flex items-center gap-2.5">
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                    <span>{urlError}</span>
                  </div>
                )}
              </div>

              {urlScanning && (
                <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-8 text-center space-y-3">
                  <RefreshCw className="w-6 h-6 text-blue-500 animate-spin mx-auto" />
                  <p className="text-sm font-medium text-white">
                    Executing Live DNS Resolution, RDAP Lookup, TLS Handshake & DNSBL Checks...
                  </p>
                  <p className="text-xs text-slate-400 font-mono">
                    Target: {urlInput}
                  </p>
                </div>
              )}

              {!urlScanning && urlResult && (
                <ScanResultView
                  scanType="url"
                  target={urlResult.target}
                  scanId={urlResult.scanId}
                  scanStatus="Live"
                  data={urlResult.data}
                  onCreateReport={handleCreateReport}
                  onAskGeminiAboutScan={handleAskGeminiAboutScan}
                  onStartVoiceTriage={(topic) => {
                    setVoiceInitialTopic(topic);
                    setVoiceModalOpen(true);
                  }}
                />
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 2. MESSAGE NLP SCANNER WORKSPACE                                  */}
          {/* ================================================================= */}
          {activeSection === 'message-scanner' && (
            <div className="space-y-8">
              <div className="bg-[#0b1325] border border-slate-800/80 rounded-xl p-6 space-y-5 shadow-sm">
                <div className="space-y-1">
                  <h2 className="text-xl font-bold text-white font-display">
                    NLP Message, Email & SMS Phishing Scanner
                  </h2>
                  <p className="text-xs text-slate-400">
                    Detects psychological coercion, urgency triggers, credential/OTP harvesting,
                    financial diversion lures, SPF/DKIM/DMARC header anomalies, and automatically
                    executes a live URL/DNS/RDAP scan on embedded links.
                  </p>
                </div>

                <form onSubmit={handleRunMessageScan} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="block text-xs font-medium text-slate-300">
                        Declared Sender Address / Display Name (Optional)
                      </label>
                      <input
                        type="text"
                        value={msgSender}
                        onChange={(e) => setMsgSender(e.target.value)}
                        placeholder='e.g., "Microsoft Security Team" <alert-help88@gmail.com>'
                        className="w-full px-3.5 py-2 text-xs font-mono bg-slate-900 border border-slate-700 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="block text-xs font-medium text-slate-300">
                        Raw Email Authentication Headers (Optional SPF / DKIM / DMARC)
                      </label>
                      <input
                        type="text"
                        value={msgHeaders}
                        onChange={(e) => setMsgHeaders(e.target.value)}
                        placeholder="e.g., Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail"
                        className="w-full px-3.5 py-2 text-xs font-mono bg-slate-900 border border-slate-700 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <label className="block text-xs font-medium text-slate-300">
                        Message Body (Email, SMS, or Instant Message Content)
                      </label>
                      <div className="flex items-center gap-2">
                        {!msgAudioRecording ? (
                          <button
                            type="button"
                            disabled={msgTranscribing}
                            onClick={handleStartMessageAudioRecord}
                            className="px-2.5 py-1 text-[11px] font-medium text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 rounded flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                            title="Record audio to transcribe with gemini-3.5-transcribe"
                          >
                            <Mic className="w-3 h-3 text-emerald-400" />
                            <span>{msgTranscribing ? 'Transcribing...' : 'Dictate (gemini-3.5-transcribe)'}</span>
                          </button>
                        ) : (
                          <button
                            type="button"
                            onClick={handleStopMessageAudioRecord}
                            className="px-2.5 py-1 text-[11px] font-semibold text-white bg-red-600 hover:bg-red-700 rounded flex items-center gap-1.5 cursor-pointer animate-pulse"
                            title="Stop recording and transcribe"
                          >
                            <MicOff className="w-3 h-3" />
                            <span>Stop & Transcribe</span>
                          </button>
                        )}

                        <label className="px-2.5 py-1 text-[11px] font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded flex items-center gap-1.5 cursor-pointer">
                          <Upload className="w-3 h-3 text-slate-400" />
                          <span>Audio File</span>
                          <input
                            type="file"
                            accept="audio/*"
                            onChange={handleMessageAudioFileUpload}
                            className="hidden"
                          />
                        </label>
                      </div>
                    </div>
                    <textarea
                      rows={5}
                      required
                      value={msgInput}
                      onChange={(e) => setMsgInput(e.target.value)}
                      placeholder="Paste suspicious email text, SMS notification, or chat message here..."
                      className="w-full p-3.5 text-sm bg-slate-900 border border-slate-700 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                    />
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="text-slate-400">Load Sample:</span>
                      <button
                        type="button"
                        onClick={() => {
                          setMsgSender('"PayPal Billing Department" <service-alert991@gmail.com>');
                          setMsgHeaders(
                            'Authentication-Results: mx.google.com; spf=softfail; dkim=fail; dmarc=fail\nFrom: service-alert991@gmail.com\nReply-To: WireSupport@protonmail.com'
                          );
                          setMsgInput(
                            'URGENT NOTICE: Dear Valued Customer, your account has been suspended due to unauthorized login activity. Immediate action is required within 24 hours to verify your password and 6-digit verification code at http://neverssl.com or your account will be permanently closed.'
                          );
                        }}
                        className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded text-[11px] font-mono cursor-pointer whitespace-nowrap"
                      >
                        Credential Phish + Header Fail
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setMsgSender('release-notify@github.com');
                          setMsgHeaders(
                            'Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass'
                          );
                          setMsgInput(
                            'Hi team, the scheduled quarterly infrastructure maintenance for https://github.com has been completed on time. No action is required from engineering.'
                          );
                        }}
                        className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded text-[11px] font-mono cursor-pointer whitespace-nowrap"
                      >
                        Legitimate Engineering Notice
                      </button>
                    </div>

                    <button
                      type="submit"
                      disabled={msgScanning}
                      className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-sm rounded-md transition-colors flex items-center gap-2 whitespace-nowrap cursor-pointer shadow-sm"
                    >
                      <MessageSquareWarning className="w-4 h-4" />
                      <span>{msgScanning ? 'Analyzing NLP & Embedded Links...' : 'Analyze Message'}</span>
                    </button>
                  </div>
                </form>

                {msgError && (
                  <div className="p-3.5 rounded-md bg-red-500/10 border border-red-500/30 text-xs text-red-400 flex items-center gap-2.5">
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                    <span>{msgError}</span>
                  </div>
                )}
              </div>

              {msgScanning && (
                <div className="bg-[#0b1325] border border-slate-800 rounded-lg p-8 text-center space-y-3">
                  <RefreshCw className="w-6 h-6 text-emerald-400 animate-spin mx-auto" />
                  <p className="text-sm font-medium text-white">
                    Running NLP Intent Classification, Header Verification & Embedded URL Deep Scan...
                  </p>
                </div>
              )}

              {!msgScanning && msgResult && (
                <ScanResultView
                  scanType="message"
                  target={msgResult.target}
                  scanId={msgResult.scanId}
                  scanStatus="Live"
                  data={msgResult.data}
                  onCreateReport={handleCreateReport}
                  onAskGeminiAboutScan={handleAskGeminiAboutScan}
                  onStartVoiceTriage={(topic) => {
                    setVoiceInitialTopic(topic);
                    setVoiceModalOpen(true);
                  }}
                />
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 2b. SCREENSHOT & VISION SCANNER WORKSPACE                         */}
          {/* ================================================================= */}
          {activeSection === 'screenshot-scanner' && (
            <ScreenshotScannerWorkspace
              onScanComplete={async (res) => {
                if (user && res.data) {
                  try {
                    const summaryText =
                      res.data.aiExplanation?.executiveSummary ||
                      `Screenshot ${res.target} analyzed. Risk Score: ${res.data.riskScore}/100 (${res.data.verdict}).`;
                    const scanId = await saveScanRecord({
                      userId: user.uid,
                      scanType: 'screenshot',
                      target: res.target,
                      riskScore: res.data.riskScore || 0,
                      verdict: res.data.verdict || 'Clean',
                      summary: summaryText,
                      analysisData: res.data,
                    });
                    res.scanId = scanId;
                  } catch (e) {
                    console.error('Failed to save screenshot scan record:', e);
                  }
                }
              }}
              onCreateReport={handleCreateReport}
              onAskGeminiAboutScan={handleAskGeminiAboutScan}
              onStartVoiceTriage={(topic) => {
                setVoiceInitialTopic(topic);
                setVoiceModalOpen(true);
              }}
            />
          )}

          {/* ================================================================= */}
          {/* 2c. QR CODE SECURITY SCANNER WORKSPACE (QUISHING DEFENSE)         */}
          {/* ================================================================= */}
          {activeSection === 'qr-scanner' && (
            <QrScannerWorkspace
              onScanComplete={async (res) => {
                if (user && res.data) {
                  try {
                    const summaryText =
                      res.data.aiExplanation?.executiveSummary ||
                      `QR payload (${res.data.payloadType || 'text'}) analyzed. Risk Score: ${res.data.riskScore}/100 (${res.data.verdict}).`;
                    const scanId = await saveScanRecord({
                      userId: user.uid,
                      scanType: 'qr',
                      target: res.target,
                      riskScore: res.data.riskScore || 0,
                      verdict: res.data.verdict || 'Clean',
                      summary: summaryText,
                      analysisData: res.data,
                    });
                    res.scanId = scanId;
                  } catch (e) {
                    console.error('Failed to save QR scan record:', e);
                  }
                }
              }}
              onCreateReport={handleCreateReport}
              onAskGeminiAboutScan={handleAskGeminiAboutScan}
              onStartVoiceTriage={(topic) => {
                setVoiceInitialTopic(topic);
                setVoiceModalOpen(true);
              }}
            />
          )}

          {/* ================================================================= */}
          {/* 3. PUBLIC IP SCANNER WORKSPACE                                    */}
          {/* ================================================================= */}
          {activeSection === 'ip-scanner' && (
            <div className="space-y-8">
              <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-5 shadow-sm">
                <div className="space-y-1">
                  <h2 className="text-xl font-bold text-white font-display">
                    Public IP Reputation, ASN, RDAP & DNSBL Scanner
                  </h2>
                  <p className="text-xs text-slate-400">
                    Performs RFC scope classification, Reverse DNS (PTR) lookup, ASN/ISP routing
                    resolution, RDAP Regional Internet Registry queries, and live multi-zone DNSBL
                    abuse checks.
                  </p>
                </div>

                <form onSubmit={(e) => handleRunIpScan(e)} className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1 relative">
                    <Network className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                    <input
                      type="text"
                      required
                      value={ipInput}
                      onChange={(e) => setIpInput(e.target.value)}
                      placeholder="Enter IPv4 or IPv6 address (e.g., 1.1.1.1 or 8.8.8.8)"
                      className="w-full pl-10 pr-4 py-2.5 text-sm font-mono bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 tabular-nums"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={ipScanning}
                    className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-sm rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap cursor-pointer shadow-sm"
                  >
                    <Search className="w-4 h-4" />
                    <span>{ipScanning ? 'Scanning IP...' : 'Analyze IP'}</span>
                  </button>
                  <button
                    type="button"
                    disabled={ipScanning}
                    onClick={handleDetectAndScanMyIp}
                    className="px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 font-medium text-xs rounded-lg transition-colors whitespace-nowrap cursor-pointer"
                  >
                    Scan My Public IP
                  </button>
                </form>

                <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                  <span className="text-slate-400">Sample Public IPs:</span>
                  {[
                    { label: '1.1.1.1 (Cloudflare DNS)', ip: '1.1.1.1' },
                    { label: '8.8.8.8 (Google Public DNS)', ip: '8.8.8.8' },
                    { label: '93.184.215.14 (IANA Example)', ip: '93.184.215.14' },
                    { label: '192.168.1.1 (Private RFC 1918)', ip: '192.168.1.1' },
                  ].map((item) => (
                    <button
                      key={item.ip}
                      type="button"
                      disabled={ipScanning}
                      onClick={() => handleRunIpScan(undefined, item.ip)}
                      className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded text-[11px] font-mono transition-colors cursor-pointer whitespace-nowrap"
                    >
                      {item.label}
                    </button>
                  ))}
                </div>

                {ipError && (
                  <div className="p-3.5 rounded-md bg-red-500/10 border border-red-500/30 text-xs text-red-400 flex items-center gap-2.5">
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                    <span>{ipError}</span>
                  </div>
                )}
              </div>

              {ipScanning && (
                <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-8 text-center space-y-3">
                  <RefreshCw className="w-6 h-6 text-emerald-400 animate-spin mx-auto" />
                  <p className="text-sm font-medium text-white">
                    Querying Reverse DNS (PTR), ASN Routing, RDAP Registry & 4 Live DNSBL Zones...
                  </p>
                </div>
              )}

              {!ipScanning && ipResult && (
                <ScanResultView
                  scanType="ip"
                  target={ipResult.target}
                  scanId={ipResult.scanId}
                  scanStatus="Live"
                  data={ipResult.data}
                  onCreateReport={handleCreateReport}
                  onAskGeminiAboutScan={handleAskGeminiAboutScan}
                  onStartVoiceTriage={(topic) => {
                    setVoiceInitialTopic(topic);
                    setVoiceModalOpen(true);
                  }}
                />
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 3b. DOMAIN INTELLIGENCE WORKSPACE                                 */}
          {/* ================================================================= */}
          {activeSection === 'domain-intel' && (
            <DomainIntelWorkspace
              onScanComplete={async (res) => {
                if (user && res.data) {
                  try {
                    const summaryText =
                      res.data.aiExplanation?.executiveSummary ||
                      `Domain ${res.target} analyzed. Risk Score: ${res.data.riskScore}/100 (${res.data.verdict}). Age: ${res.data.rdap?.domainAgeDays !== undefined && res.data.rdap?.domainAgeDays !== null ? `${res.data.rdap.domainAgeDays} days` : 'Unavailable'}.`;
                    const scanId = await saveScanRecord({
                      userId: user.uid,
                      scanType: 'domain',
                      target: res.target,
                      riskScore: res.data.riskScore || 0,
                      verdict: res.data.verdict || 'Clean',
                      summary: summaryText,
                      analysisData: res.data,
                    });
                    res.scanId = scanId;
                  } catch (e) {
                    console.error('Failed to save domain scan record:', e);
                  }
                }
              }}
              onCreateReport={handleCreateReport}
              onAskGeminiAboutScan={handleAskGeminiAboutScan}
              onStartVoiceTriage={(topic) => {
                setVoiceInitialTopic(topic);
                setVoiceModalOpen(true);
              }}
            />
          )}

          {/* ================================================================= */}
          {/* 3c. THREE.JS 3D CYBER DEFENSE MATRIX & SPATIAL RADAR              */}
          {/* ================================================================= */}
          {activeSection === 'cyber-matrix-3d' && (
            <div className="space-y-6">
              <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <h2 className="text-xl font-bold text-white font-display">
                      3D Cyber Defense Aegis Matrix & Threat Interceptor
                    </h2>
                    <p className="text-xs text-slate-400">
                      Real-time Three.js spatial threat environment featuring a composite 12-part procedural shield core, RoomEnvironment PBR lighting, radar sweeps, and live threat telemetry dissipation.
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-slate-400">
                      {scans.length} Authenticated Scan{scans.length === 1 ? '' : 's'} Synchronized
                    </span>
                  </div>
                </div>
              </div>

              {/* Three.js 3D Viewport with Collapsible Bottom Control Dock */}
              <CyberMatrix3D
                scans={scans}
                recentScan={
                  urlResult
                    ? { target: urlResult.target, riskScore: urlResult.data.riskScore, verdict: urlResult.data.verdict, scanType: 'URL' }
                    : msgResult
                      ? { target: msgResult.target, riskScore: msgResult.data.riskScore, verdict: msgResult.data.verdict, scanType: 'Message' }
                      : ipResult
                        ? { target: ipResult.target, riskScore: ipResult.data.riskScore, verdict: ipResult.data.verdict, scanType: 'IP' }
                        : null
                }
              />
            </div>
          )}

          {/* ================================================================= */}
          {/* 3b. LIVE VOICE ASSISTANT WORKSPACE (gemini-3.8-live)               */}
          {/* ================================================================= */}
          {activeSection === 'live-voice' && (
            <div className="space-y-6">
              <LiveVoiceAssistant
                onSendTranscriptToMessageScanner={(transcript) => {
                  setMsgInput(transcript);
                  setActiveSection('message-scanner');
                }}
              />
            </div>
          )}

          {/* ================================================================= */}
          {/* 4. GEMINI AI ASSISTANT & SOC STUDIO WORKSPACE                     */}
          {/* ================================================================= */}
          {activeSection === 'ai-assistant' && (
            <AiSecuritySuite
              user={user}
              chatSessions={chatSessions}
              recentScans={scans}
              initialPrompt={suiteInitialPrompt}
              onConsumeInitialPrompt={() => setSuiteInitialPrompt(null)}
              authenticatedFetch={authenticatedFetch}
              onSendTranscriptToMessageScanner={(transcript) => {
                setMsgInput(transcript);
                setActiveSection('message-scanner');
              }}
            />
          )}

          {/* ================================================================= */}
          {/* 5. SCAN HISTORY WORKSPACE                                         */}
          {/* ================================================================= */}
          {activeSection === 'scan-history' && (
            <div className="space-y-6">
              {/* Recharts Line Chart: Temporal Risk Score Trends Over Time Filtered by Date Range */}
              <ScanRiskTrendsChart
                scans={scans}
                selectedDate={historyDateFilter}
                onSelectDate={setHistoryDateFilter}
                onInspectScan={(scan) => setSelectedHistoryScan(scan)}
              />

              {/* D3 Heatmap Visualization of Temporal Risk Scores Categorized by Date */}
              <ScanHistoryHeatmap
                scans={scans}
                selectedDate={historyDateFilter}
                onSelectDate={setHistoryDateFilter}
                onInspectScan={(scan) => setSelectedHistoryScan(scan)}
                riskCategoryFilter={historyRiskCategory}
                onRiskCategoryChange={setHistoryRiskCategory}
              />

              <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-5 shadow-sm">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <h2 className="text-xl font-bold text-white font-display">
                      Authenticated Scan Audit Ledger
                    </h2>
                    <p className="text-xs text-slate-400">
                      All scans are cryptographically bound to your UID ({user.uid.slice(0, 14)}...)
                      and immutable once recorded.
                    </p>
                  </div>

                  {/* Interactive Filter Bar */}
                  <div className="flex flex-wrap items-center gap-3">
                    {historyDateFilter && (
                      <div className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-md text-xs font-mono">
                        <Calendar className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Date: {historyDateFilter}</span>
                        <button
                          type="button"
                          onClick={() => setHistoryDateFilter(null)}
                          className="ml-1 text-emerald-300 hover:text-white cursor-pointer"
                          title="Clear date filter"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </div>
                    )}

                    {historyRiskCategory !== 'all' && (
                      <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-900 border border-slate-700 text-slate-300 rounded-md text-xs font-mono">
                        <span
                          className={`w-2 h-2 rounded-full inline-block ${
                            historyRiskCategory === 'high'
                              ? 'bg-red-500'
                              : historyRiskCategory === 'medium'
                                ? 'bg-amber-400'
                                : 'bg-emerald-400'
                          }`}
                        />
                        <span className="capitalize">Risk: {historyRiskCategory}</span>
                        <button
                          type="button"
                          onClick={() => setHistoryRiskCategory('all')}
                          className="ml-1 text-slate-400 hover:text-white cursor-pointer"
                          title="Clear risk category filter"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </div>
                    )}

                    <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-700 rounded-md">
                      {(['all', 'url', 'message', 'ip'] as const).map((type) => (
                        <button
                          key={type}
                          type="button"
                          onClick={() => setHistoryFilter(type)}
                          className={`px-3 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                            historyFilter === type
                              ? 'bg-blue-600 text-white shadow-xs'
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          {type === 'all' ? 'All Vectors' : type.toUpperCase()}
                        </button>
                      ))}
                    </div>

                    <div className="relative">
                      <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        value={historySearch}
                        onChange={(e) => setHistorySearch(e.target.value)}
                        placeholder="Filter target or verdict..."
                        className="pl-8 pr-3 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                      />
                    </div>
                  </div>
                </div>

                {dataLoading ? (
                  <div className="py-12 text-center text-xs font-mono text-slate-400">
                    Synchronizing scan ledger from Firestore...
                  </div>
                ) : filteredScans.length === 0 ? (
                  <div className="py-12 text-center space-y-3 border-t border-slate-800">
                    <p className="text-sm text-slate-400">No security scans match the current view.</p>
                    <button
                      type="button"
                      onClick={() => setActiveSection('url-scanner')}
                      className="px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-md cursor-pointer"
                    >
                      Launch First Security Scan
                    </button>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2.5 pr-4 font-medium">Vector</th>
                          <th className="py-2.5 px-4 font-medium">Inspected Target</th>
                          <th className="py-2.5 px-4 font-medium">Verdict</th>
                          <th className="py-2.5 px-4 font-medium text-right">Risk Score</th>
                          <th className="py-2.5 px-4 font-medium">Timestamp</th>
                          <th className="py-2.5 pl-4 font-medium text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {filteredScans.map((scan) => (
                          <tr
                            key={scan.scanId}
                            className="hover:bg-slate-900/50 transition-colors"
                          >
                            <td className="py-3 pr-4 font-mono uppercase text-slate-400">
                              {scan.scanType}
                            </td>
                            <td className="py-3 px-4 font-mono text-slate-200 max-w-md truncate">
                              {scan.target}
                            </td>
                            <td className="py-3 px-4 font-semibold">
                              <span
                                className={
                                  scan.riskScore >= 50
                                    ? 'text-red-400'
                                    : scan.riskScore >= 25
                                      ? 'text-amber-400'
                                      : 'text-emerald-400'
                                }
                              >
                                {scan.verdict}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-right font-mono tabular-nums font-semibold text-white">
                              {scan.riskScore}/100
                            </td>
                            <td className="py-3 px-4 font-mono text-slate-400 tabular-nums whitespace-nowrap">
                              {scan.createdAt?.toDate
                                ? scan.createdAt.toDate().toLocaleString()
                                : 'Just now'}
                            </td>
                            <td className="py-3 pl-4 text-right whitespace-nowrap">
                              <div className="inline-flex items-center gap-2">
                                <button
                                  type="button"
                                  onClick={() => setSelectedHistoryScan(scan)}
                                  className="px-2.5 py-1 text-xs font-medium text-blue-400 hover:text-white hover:bg-blue-600/20 rounded transition-colors cursor-pointer"
                                >
                                  Inspect
                                </button>
                                <button
                                  type="button"
                                  onClick={() => deleteScanRecord(scan.scanId)}
                                  className="p-1 text-slate-500 hover:text-red-400 transition-colors cursor-pointer"
                                  title="Delete Scan Record"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {selectedHistoryScan && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-slate-200">
                      Archived Telemetry Inspection ({selectedHistoryScan.scanId})
                    </h3>
                    <button
                      type="button"
                      onClick={() => setSelectedHistoryScan(null)}
                      className="text-xs text-slate-400 hover:text-white cursor-pointer"
                    >
                      Close Inspection View
                    </button>
                  </div>
                  <ScanResultView
                    scanType={selectedHistoryScan.scanType}
                    target={selectedHistoryScan.target}
                    scanId={selectedHistoryScan.scanId}
                    scanStatus="Historical"
                    data={selectedHistoryScan.analysisData}
                    onCreateReport={handleCreateReport}
                    onAskGeminiAboutScan={handleAskGeminiAboutScan}
                    onStartVoiceTriage={(topic) => {
                      setVoiceInitialTopic(topic);
                      setVoiceModalOpen(true);
                    }}
                  />
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 6. SECURITY REPORTS WORKSPACE                                     */}
          {/* ================================================================= */}
          {activeSection === 'security-reports' && (
            <div className="space-y-6">
              <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-5 shadow-sm">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <h2 className="text-xl font-bold text-white font-display">
                      Formal Security & Incident Reports
                    </h2>
                    <p className="text-xs text-slate-400">
                      Annotate scan findings, export executive incident briefs, or archive finalized
                      reports to lock them against further edits.
                    </p>
                  </div>

                  <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-700 rounded-md self-start">
                    {(['all', 'active', 'archived'] as const).map((status) => (
                      <button
                        key={status}
                        type="button"
                        onClick={() => setReportFilter(status)}
                        className={`px-3 py-1 text-xs font-medium rounded transition-colors cursor-pointer capitalize whitespace-nowrap ${
                          reportFilter === status
                            ? 'bg-blue-600 text-white shadow-xs'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        {status}
                      </button>
                    ))}
                  </div>
                </div>

                {filteredReports.length === 0 ? (
                  <div className="py-12 text-center space-y-3 border-t border-slate-800">
                    <p className="text-sm text-slate-400">
                      No security reports generated yet. Run any scan and click “Generate Security
                      Report”.
                    </p>
                    <button
                      type="button"
                      onClick={() => setActiveSection('url-scanner')}
                      className="px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-md cursor-pointer"
                    >
                      Go to URL Scanner
                    </button>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-2">
                    {/* Reports List (5 cols) */}
                    <div className="lg:col-span-5 divide-y divide-slate-800 border border-slate-800 rounded-lg bg-slate-950/70">
                      {filteredReports.map((rep) => {
                        const isSelected = selectedReport?.reportId === rep.reportId;
                        return (
                          <div
                            key={rep.reportId}
                            onClick={() => {
                              setSelectedReport(rep);
                              setEditReportTitle(rep.title);
                              setEditReportNotes(rep.analystNotes);
                              setReportFeedback(null);
                            }}
                            className={`p-4 cursor-pointer transition-colors space-y-1.5 ${
                              isSelected ? 'bg-blue-600/15 border-l-2 border-l-blue-500' : 'hover:bg-slate-900/60'
                            }`}
                          >
                            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                              <span>
                                {rep.scanType.toUpperCase()} · {rep.status.toUpperCase()}
                              </span>
                              <span className="tabular-nums">Score: {rep.riskScore}/100</span>
                            </div>
                            <p className="text-xs font-semibold text-white truncate">
                              {rep.title}
                            </p>
                            <p className="text-[11px] font-mono text-slate-400 truncate">
                              {rep.target}
                            </p>
                          </div>
                        );
                      })}
                    </div>

                    {/* Report Detail & Editor (7 cols) */}
                    <div className="lg:col-span-7 border border-slate-800 rounded-lg bg-slate-950/40 p-5">
                      {selectedReport ? (
                        <div className="space-y-4">
                          <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800">
                            <div className="text-xs font-mono text-slate-400">
                              <span>ID: {selectedReport.reportId}</span>
                              <span className="mx-2">·</span>
                              <span>
                                Status:{' '}
                                <strong className="text-white uppercase">
                                  {selectedReport.status}
                                </strong>
                              </span>
                            </div>

                            <div className="flex items-center gap-2">
                              <button
                                type="button"
                                onClick={() => handleDownloadReportMarkdown(selectedReport)}
                                className="px-2.5 py-1 text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded flex items-center gap-1.5 cursor-pointer"
                              >
                                <Download className="w-3.5 h-3.5" />
                                <span>Export .MD</span>
                              </button>
                              {selectedReport.status === 'active' && (
                                <button
                                  type="button"
                                  onClick={async () => {
                                    await archiveSecurityReport(selectedReport.reportId);
                                    setSelectedReport({
                                      ...selectedReport,
                                      status: 'archived',
                                    });
                                    setReportFeedback(
                                      'Report archived and locked in terminal state.'
                                    );
                                  }}
                                  className="px-2.5 py-1 text-xs font-medium bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded flex items-center gap-1.5 cursor-pointer"
                                >
                                  <Archive className="w-3.5 h-3.5" />
                                  <span>Archive & Lock</span>
                                </button>
                              )}
                              <button
                                type="button"
                                onClick={async () => {
                                  await deleteSecurityReport(selectedReport.reportId);
                                  setSelectedReport(null);
                                }}
                                className="p-1 text-slate-400 hover:text-red-400 cursor-pointer"
                                title="Delete Report"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </div>

                          {reportFeedback && (
                            <div className="p-2.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400">
                              {reportFeedback}
                            </div>
                          )}

                          <div className="space-y-1.5">
                            <label className="block text-xs font-medium text-slate-300">
                              Report Title
                            </label>
                            <input
                              type="text"
                              disabled={selectedReport.status === 'archived'}
                              value={editReportTitle}
                              onChange={(e) => setEditReportTitle(e.target.value)}
                              maxLength={200}
                              className="w-full px-3 py-2 text-xs bg-slate-900 border border-slate-700 rounded text-white disabled:opacity-60 focus:outline-none focus:border-blue-500"
                            />
                          </div>

                          <div className="space-y-1.5">
                            <label className="block text-xs font-medium text-slate-300">
                              Analyst Investigation Notes & Remediation Plan
                            </label>
                            <textarea
                              rows={8}
                              disabled={selectedReport.status === 'archived'}
                              value={editReportNotes}
                              onChange={(e) => setEditReportNotes(e.target.value)}
                              maxLength={5000}
                              className="w-full p-3 text-xs font-mono bg-slate-900 border border-slate-700 rounded text-slate-200 disabled:opacity-60 leading-relaxed focus:outline-none focus:border-blue-500"
                            />
                          </div>

                          {selectedReport.status === 'active' ? (
                            <button
                              type="button"
                              disabled={savingReportEdit}
                              onClick={async () => {
                                setSavingReportEdit(true);
                                setReportFeedback(null);
                                try {
                                  await updateSecurityReportNotes(
                                    selectedReport.reportId,
                                    editReportTitle,
                                    editReportNotes
                                  );
                                  setReportFeedback('Report changes saved to Firestore.');
                                } finally {
                                  setSavingReportEdit(false);
                                }
                              }}
                              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs rounded cursor-pointer"
                            >
                              {savingReportEdit ? 'Saving...' : 'Save Report Updates'}
                            </button>
                          ) : (
                            <p className="text-xs text-amber-400 font-mono">
                              This report is archived (terminal state) and locked from further
                              modifications by Firestore security rules.
                            </p>
                          )}
                        </div>
                      ) : (
                        <div className="py-16 text-center text-xs text-slate-400">
                          Select a report from the left column to view, annotate, or export.
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ================================================================= */}
          {/* 6b. SECURITY AWARENESS & TRAINING WORKSPACE                       */}
          {/* ================================================================= */}
          {activeSection === 'security-awareness' && (
            <SecurityAwarenessWorkspace />
          )}

          {/* ================================================================= */}
          {/* 6c. SECURITY ANALYTICS & RISK TELEMETRY WORKSPACE                 */}
          {/* ================================================================= */}
          {activeSection === 'security-analytics' && (
            <SecurityAnalyticsWorkspace scans={scans} />
          )}

          {/* ================================================================= */}
          {/* 7. USER PROFILE & SECURITY WORKSPACE                              */}
          {/* ================================================================= */}
          {activeSection === 'user-profile' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Public Analyst Profile Editor (7 cols) */}
              <div className="lg:col-span-7 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-5 shadow-sm">
                <div className="space-y-1 border-b border-slate-800 pb-3">
                  <h2 className="text-lg font-bold text-white font-display">
                    Analyst Identity & Workspace Profile
                  </h2>
                  <p className="text-xs text-slate-400">
                    Stored in `/users/{'{userId}'}` with strict key & length validation.
                  </p>
                </div>

                {profileFeedback && (
                  <div className="p-3 rounded bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>{profileFeedback}</span>
                  </div>
                )}

                <form onSubmit={handleSaveProfile} className="space-y-4">
                  <div className="space-y-1.5">
                    <label className="block text-xs font-medium text-slate-300">
                      Analyst Display Name
                    </label>
                    <input
                      type="text"
                      required
                      maxLength={100}
                      value={profileName}
                      onChange={(e) => setProfileName(e.target.value)}
                      className="w-full px-3.5 py-2 text-sm bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="block text-xs font-medium text-slate-300">
                      Organization / Security Team
                    </label>
                    <input
                      type="text"
                      maxLength={120}
                      value={profileOrg}
                      onChange={(e) => setProfileOrg(e.target.value)}
                      className="w-full px-3.5 py-2 text-sm bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="block text-xs font-medium text-slate-300">Role / Title</label>
                    <input
                      type="text"
                      maxLength={100}
                      value={profileJob}
                      onChange={(e) => setProfileJob(e.target.value)}
                      className="w-full px-3.5 py-2 text-sm bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={savingProfile}
                    className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-colors cursor-pointer shadow-sm"
                  >
                    {savingProfile ? 'Saving Profile...' : 'Update Analyst Profile'}
                  </button>
                </form>
              </div>

              {/* Isolated PII & Session Controls (5 cols) */}
              <div className="lg:col-span-5 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-5 shadow-sm">
                <div className="space-y-1 border-b border-slate-800 pb-3">
                  <h3 className="text-lg font-bold text-white font-display">
                    Isolated PII Vault & Session Security
                  </h3>
                  <p className="text-xs text-slate-400">
                    Isolated inside `/users/{'{userId}'}/private/info` per Zero-Trust PII separation.
                  </p>
                </div>

                <dl className="space-y-3 text-xs">
                  <div className="flex justify-between py-1.5 border-b border-slate-800">
                    <dt className="text-slate-400">Authenticated UID</dt>
                    <dd className="font-mono text-slate-200">{user.uid.slice(0, 18)}...</dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800">
                    <dt className="text-slate-400">Primary Auth Provider</dt>
                    <dd className="font-mono text-emerald-400 font-semibold">
                      {privateInfo?.authProvider || user.providerData?.[0]?.providerId || 'firebase'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800">
                    <dt className="text-slate-400">Verified Email</dt>
                    <dd className="font-mono text-slate-200">
                      {privateInfo?.email || user.email || 'Not Linked'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800">
                    <dt className="text-slate-400">Phone Number</dt>
                    <dd className="font-mono text-slate-200 tabular-nums">
                      {privateInfo?.phoneNumber || user.phoneNumber || 'Not Linked'}
                    </dd>
                  </div>
                </dl>

                <div className="pt-2 space-y-2.5">
                  {user.email && (
                    <button
                      type="button"
                      onClick={handlePasswordResetRequest}
                      className="w-full py-2 px-3 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-md transition-colors flex items-center justify-center gap-2 cursor-pointer"
                    >
                      <Lock className="w-3.5 h-3.5 text-blue-400" />
                      <span>Send Password Reset Link to {user.email}</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => signOut(auth)}
                    className="w-full py-2 px-3 text-xs font-medium text-red-400 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 rounded-md transition-colors flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Terminate Session & Sign Out</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ================================================================= */}
          {/* 8. SECURITY SETTINGS & 12-SUBSYSTEM HEALTH DASHBOARD              */}
          {/* ================================================================= */}
          {activeSection === 'security-settings' && (
            <SecuritySettingsWorkspace />
          )}
        </main>
      </div>

      {/* ===================================================================== */}
      {/* OMNIPRESENT SLIDE-OVER GEMINI AI SECURITY ASSISTANT COPILOT DRAWER    */}
      {/* ===================================================================== */}
      {copilotDrawerOpen && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#070d19] border-l border-slate-800 h-full flex flex-col shadow-2xl">
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between gap-3 bg-[#070d19]">
              <div className="flex items-center gap-2 min-w-0">
                <Sparkles className="w-4 h-4 text-blue-400 shrink-0" />
                <div className="min-w-0">
                  <h3 className="text-sm font-bold text-white font-display truncate">
                    Gemini AI Security Assistant
                  </h3>
                  <p className="text-[11px] text-slate-400 font-mono truncate">
                    Live Tool Calling · Search Grounding · TTS Audio
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => {
                    setCopilotDrawerOpen(false);
                    setActiveSection('ai-assistant');
                  }}
                  className="px-2.5 py-1 text-[11px] font-medium text-blue-400 bg-blue-600/15 hover:bg-blue-600/25 border border-blue-500/30 rounded flex items-center gap-1 cursor-pointer"
                  title="Open Full Gemini AI Studio (Voice, Transcribe, Maps, Veo 3)"
                >
                  <Maximize2 className="w-3 h-3" />
                  <span>Full Studio</span>
                </button>
                <button
                  type="button"
                  onClick={() => setCopilotDrawerOpen(false)}
                  className="p-1 text-slate-400 hover:text-white cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Model Selector & Active Scan Context Indicator */}
            <div className="px-5 py-2.5 border-b border-slate-800 bg-[#050914] flex items-center justify-between gap-2 text-xs">
              <select
                value={drawerModel}
                onChange={(e) => setDrawerModel(e.target.value as any)}
                className="px-2.5 py-1 bg-slate-900 border border-slate-700 rounded text-white font-mono text-[11px] focus:outline-none focus:border-blue-500"
              >
                <option value="gemini-3.8-flash">gemini-3.8-flash (General Tasks)</option>
                <option value="gemini-3.1-flash-lite">gemini-3.1-flash-lite (Fast Tasks)</option>
                <option value="gemini-4-argon">gemini-4-argon (Complex Tasks)</option>
              </select>

              {activeWorkspaceScanContext ? (
                <span className="text-[11px] font-mono text-emerald-400 truncate">
                  Context: {activeWorkspaceScanContext.label}
                </span>
              ) : (
                <span className="text-[11px] font-mono text-slate-400">
                  Live Scanners Active
                </span>
              )}
            </div>

            {/* Messages Area */}
            <div
              ref={drawerScrollRef}
              className="flex-1 p-4 overflow-y-auto space-y-3.5 bg-[#030712]"
            >
              {drawerMessages.length === 0 ? (
                <div className="py-8 text-center space-y-4">
                  <div className="w-9 h-9 rounded-full bg-blue-600/10 border border-blue-500/30 flex items-center justify-center text-blue-400 mx-auto">
                    <Sparkles className="w-4 h-4" />
                  </div>
                  <div className="space-y-1 px-2">
                    <p className="text-xs font-semibold text-white">
                      Ask Gemini to Scan Targets or Explain Telemetry
                    </p>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Gemini can directly execute live URL, Domain, DNS, RDAP, Public IP, and
                      Message scans via Function Calling, or analyze your current scan result.
                    </p>
                  </div>

                  <div className="space-y-1.5 text-left px-2">
                    {[
                      'Scan https://github.com/login and check its RDAP age & DNS records',
                      'Scan IP 8.8.8.8 and summarize its ASN and DNSBL status',
                      'Analyze this SMS: "URGENT: Your account is suspended, verify at http://neverssl.com"',
                      'How do I harden SPF, DKIM, and DMARC p=reject?',
                    ].map((prompt) => (
                      <button
                        key={prompt}
                        type="button"
                        onClick={() => handleSendDrawerMessage(undefined, prompt)}
                        className="w-full p-2.5 text-xs bg-[#0b1325] hover:bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-lg text-slate-300 text-left transition-colors cursor-pointer"
                      >
                        {prompt}
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                drawerMessages.map((m, idx) => (
                  <div
                    key={idx}
                    className={`flex flex-col ${
                      m.role === 'user' ? 'items-end' : 'items-start'
                    }`}
                  >
                    <div
                      className={`max-w-[90%] rounded-lg p-3 text-xs leading-relaxed whitespace-pre-wrap ${
                        m.role === 'user'
                          ? 'bg-blue-600 text-white'
                          : 'bg-[#0b1325] border border-slate-800 text-slate-200 shadow-2xs'
                      }`}
                    >
                      {Array.isArray(m.executedTools) && m.executedTools.length > 0 && (
                        <div className="mb-2.5 pb-2 border-b border-slate-800 space-y-1.5">
                          <p className="text-[10px] font-mono font-semibold text-emerald-400">
                            Executed Live Tool:
                          </p>
                          {m.executedTools.map((t, tIdx) => (
                            <div
                              key={tIdx}
                              className="p-2 rounded bg-slate-900 border border-slate-800 font-mono text-[10px] space-y-0.5"
                            >
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-semibold text-white truncate">
                                  {t.toolName}: {t.target}
                                </span>
                                <span className="text-emerald-400 font-semibold shrink-0">
                                  {t.riskScore}/100
                                </span>
                              </div>
                              <p className="text-slate-400">{t.summary}</p>
                            </div>
                          ))}
                        </div>
                      )}

                      <div>{m.text}</div>

                      {m.role === 'model' && (
                        <div className="mt-2.5 pt-2 border-t border-slate-800 flex items-center justify-between">
                          <button
                            type="button"
                            onClick={() => handlePlayDrawerTts(m.text, idx)}
                            className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-400 hover:text-white cursor-pointer"
                          >
                            <Volume2 className="w-3 h-3" />
                            <span>{drawerTtsIdx === idx ? 'Playing Audio...' : 'Listen (TTS)'}</span>
                          </button>

                          {Array.isArray(m.sources) && m.sources.length > 0 && (
                            <a
                              href={m.sources[0].uri}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-[10px] font-mono text-blue-400 hover:underline"
                            >
                              <span>{m.sources.length} Web Source(s)</span>
                              <ExternalLink className="w-2.5 h-2.5" />
                            </a>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                ))
              )}

              {drawerSending && (
                <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-400" />
                  <span>Gemini is analyzing...</span>
                </div>
              )}
            </div>

            {drawerError && (
              <div className="px-4 py-2 bg-red-500/10 border-t border-red-500/30 text-xs text-red-400">
                {drawerError}
              </div>
            )}

            <form
              onSubmit={(e) => handleSendDrawerMessage(e)}
              className="p-3.5 border-t border-slate-800 bg-[#070d19] flex items-center gap-2"
            >
              <input
                type="text"
                value={drawerInput}
                onChange={(e) => setDrawerInput(e.target.value)}
                placeholder="Ask Gemini to scan a URL/IP or explain..."
                className="flex-1 px-3 py-2 text-xs bg-slate-900 border border-slate-700 rounded-md text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
              <button
                type="submit"
                disabled={drawerSending || !drawerInput.trim()}
                className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold rounded-md flex items-center gap-1 cursor-pointer"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Floating Quick Live Voice Action Pill (Available across all screens) */}
      <div className="fixed bottom-6 right-6 z-30 flex items-center gap-2">
        <button
          type="button"
          onClick={() => {
            setVoiceInitialTopic(null);
            setVoiceModalOpen(true);
          }}
          className="flex items-center gap-2 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-full shadow-xl border border-slate-700 text-xs font-semibold cursor-pointer transition-all duration-200 hover:scale-105 active:scale-95 group"
          title="Launch Live Voice Conversation with Gemini 3.8 Live"
        >
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
          </span>
          <Radio className="w-3.5 h-3.5 text-emerald-400" />
          <span>Live Voice Copilot</span>
        </button>
      </div>

      {/* Live Voice Assistant Modal Dialog */}
      {voiceModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs">
          <div className="w-full max-w-4xl bg-[#070d19] rounded-xl shadow-2xl overflow-hidden border border-slate-800 animate-in fade-in zoom-in-95 duration-150">
            <LiveVoiceAssistant
              isModal
              initialTopic={voiceInitialTopic}
              onCloseModal={() => setVoiceModalOpen(false)}
              onSendTranscriptToMessageScanner={(transcript) => {
                setMsgInput(transcript);
                setActiveSection('message-scanner');
                setVoiceModalOpen(false);
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
}

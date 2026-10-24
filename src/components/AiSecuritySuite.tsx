import React, { useState, useRef, useEffect } from 'react';
import { User } from 'firebase/auth';
import {
  MessageSquare,
  Mic,
  MicOff,
  Radio,
  Search,
  MapPin,
  Image as ImageIcon,
  Video,
  Send,
  Plus,
  Trash2,
  ExternalLink,
  Upload,
  Sparkles,
  AlertTriangle,
  RefreshCw,
  Volume2,
  ArrowRight,
} from 'lucide-react';
import {
  ChatSessionDoc,
  ChatTurnItem,
  ScanRecordDoc,
  saveChatSession,
  deleteChatSession,
} from '../lib/firebase';

type SuiteTab = 'chat' | 'live-voice' | 'transcribe' | 'grounding' | 'media-studio';

interface AiSecuritySuiteProps {
  user: User;
  chatSessions: ChatSessionDoc[];
  recentScans?: ScanRecordDoc[];
  initialPrompt?: string | null;
  onConsumeInitialPrompt?: () => void;
  authenticatedFetch: (endpoint: string, options?: RequestInit) => Promise<any>;
  onSendTranscriptToMessageScanner?: (transcript: string) => void;
}

export const AiSecuritySuite: React.FC<AiSecuritySuiteProps> = ({
  user,
  chatSessions,
  recentScans = [],
  initialPrompt,
  onConsumeInitialPrompt,
  authenticatedFetch,
  onSendTranscriptToMessageScanner,
}) => {
  const [activeTab, setActiveTab] = useState<SuiteTab>('chat');

  // ==========================================================================
  // 1. MULTI-TURN CHATBOT STATE
  // ==========================================================================
  const [activeChatId, setActiveChatId] = useState<string | undefined>(undefined);
  const [chatTitle, setChatTitle] = useState('Gemini AI Security Investigation');
  const [selectedModel, setSelectedModel] = useState<
    'gemini-3.1-flash-lite' | 'gemini-3.8-flash' | 'gemini-4-argon' | 'gemini-3.1-pro-preview'
  >('gemini-3.8-flash');
  const [rolePersona, setRolePersona] = useState<string>('soc-analyst');
  const [chatSearchGrounding, setChatSearchGrounding] = useState<boolean>(true);
  const [enableSecurityTools, setEnableSecurityTools] = useState<boolean>(true);
  const [attachedScanId, setAttachedScanId] = useState<string>('');
  const [chatMessages, setChatMessages] = useState<ChatTurnItem[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatSending, setChatSending] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const [chatMicRecording, setChatMicRecording] = useState(false);
  const [chatMicTranscribing, setChatMicTranscribing] = useState(false);
  const chatMicRecorderRef = useRef<MediaRecorder | null>(null);
  const chatMicChunksRef = useRef<Blob[]>([]);
  const [ttsPlayingIdx, setTtsPlayingIdx] = useState<number | null>(null);
  const [ttsLoadingIdx, setTtsLoadingIdx] = useState<number | null>(null);
  const audioPlayerRef = useRef<HTMLAudioElement | null>(null);
  const chatScrollRef = useRef<HTMLDivElement | null>(null);

  const handleToggleChatMic = async () => {
    setChatError(null);
    if (chatMicRecording && chatMicRecorderRef.current) {
      chatMicRecorderRef.current.stop();
      setChatMicRecording(false);
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      chatMicChunksRef.current = [];
      const recorder = new MediaRecorder(stream);
      chatMicRecorderRef.current = recorder;

      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) chatMicChunksRef.current.push(e.data);
      };

      recorder.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(chatMicChunksRef.current, {
          type: recorder.mimeType || 'audio/webm',
        });
        setChatMicTranscribing(true);
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
              mimeType: recorder.mimeType || 'audio/webm',
            }),
          });
          if (res.transcript) {
            setChatInput((prev) => (prev ? `${prev} ${res.transcript}` : res.transcript));
          }
        } catch (err: unknown) {
          setChatError(err instanceof Error ? err.message : 'Microphone transcription failed.');
        } finally {
          setChatMicTranscribing(false);
        }
      };

      recorder.start();
      setChatMicRecording(true);
    } catch (err: unknown) {
      setChatError(
        err instanceof Error ? err.message : 'Could not access microphone for audio transcription.'
      );
    }
  };

  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [chatMessages, chatSending]);

  useEffect(() => {
    if (initialPrompt && initialPrompt.trim()) {
      setActiveTab('chat');
      const promptToRun = initialPrompt.trim();
      if (onConsumeInitialPrompt) {
        onConsumeInitialPrompt();
      }
      handleSendChatMessage(undefined, promptToRun);
    }
  }, [initialPrompt]);

  const handlePlayMessageTts = async (text: string, idx: number) => {
    if (ttsPlayingIdx === idx) {
      if (audioPlayerRef.current) {
        audioPlayerRef.current.pause();
        audioPlayerRef.current = null;
      }
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        window.speechSynthesis.cancel();
      }
      setTtsPlayingIdx(null);
      return;
    }

    if (audioPlayerRef.current) {
      audioPlayerRef.current.pause();
      audioPlayerRef.current = null;
    }
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }

    setTtsLoadingIdx(idx);
    try {
      const res = await authenticatedFetch('/api/tts', {
        method: 'POST',
        body: JSON.stringify({
          text: text.slice(0, 1500),
          voiceName: 'Kore',
        }),
      });
      if (res.audioDataUrl) {
        const audio = new Audio(res.audioDataUrl);
        audioPlayerRef.current = audio;
        setTtsPlayingIdx(idx);
        audio.onended = () => {
          setTtsPlayingIdx(null);
          audioPlayerRef.current = null;
        };
        await audio.play();
      }
    } catch {
      // Fallback to browser SpeechSynthesis if TTS model quota is reached
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        const utterance = new SpeechSynthesisUtterance(
          text.replace(/[*#`_~]/g, '').slice(0, 1200)
        );
        utterance.onend = () => setTtsPlayingIdx(null);
        utterance.onerror = () => setTtsPlayingIdx(null);
        setTtsPlayingIdx(idx);
        window.speechSynthesis.speak(utterance);
      }
    } finally {
      setTtsLoadingIdx(null);
    }
  };

  const handleSelectSavedChat = (session: ChatSessionDoc) => {
    setActiveChatId(session.chatId);
    setChatTitle(session.title);
    setRolePersona(session.rolePersona);
    if (
      session.modelName === 'gemini-3.1-flash-lite' ||
      session.modelName === 'gemini-3.8-flash' ||
      session.modelName === 'gemini-3.1-pro-preview'
    ) {
      setSelectedModel(session.modelName);
    }
    setChatMessages(Array.isArray(session.messages) ? session.messages : []);
    setChatError(null);
  };

  const handleNewChat = () => {
    setActiveChatId(undefined);
    setChatTitle('New SOC Investigation');
    setChatMessages([]);
    setChatError(null);
  };

  const handleSendChatMessage = async (e?: React.FormEvent, presetPrompt?: string) => {
    if (e) e.preventDefault();
    const text = (presetPrompt ?? chatInput).trim();
    if (!text || chatSending) return;
    if (!presetPrompt) setChatInput('');

    setChatError(null);
    const userTurn: ChatTurnItem = {
      role: 'user',
      text,
      timestamp: new Date().toISOString(),
    };
    const updatedHistory = [...chatMessages, userTurn];
    setChatMessages(updatedHistory);
    setChatSending(true);

    try {
      const selectedScan = recentScans.find((s) => s.scanId === attachedScanId);
      const attachedScanContext = selectedScan
        ? JSON.stringify(
            {
              scanId: selectedScan.scanId,
              scanType: selectedScan.scanType,
              target: selectedScan.target,
              riskScore: selectedScan.riskScore,
              verdict: selectedScan.verdict,
              summary: selectedScan.summary,
              analysisData: selectedScan.analysisData,
            },
            null,
            2
          )
        : undefined;

      const data = await authenticatedFetch('/api/chat', {
        method: 'POST',
        body: JSON.stringify({
          model: selectedModel,
          rolePersona,
          history: chatMessages.map((m) => ({ role: m.role, text: m.text })),
          message: text,
          useSearchGrounding: chatSearchGrounding,
          enableSecurityTools,
          attachedScanContext,
        }),
      });

      const modelTurn: ChatTurnItem = {
        role: 'model',
        text: data.reply || 'Analysis complete.',
        timestamp: new Date().toISOString(),
        sources: Array.isArray(data.webSources) ? data.webSources : undefined,
        executedTools: Array.isArray(data.executedTools) ? data.executedTools : undefined,
      };

      const finalMessages = [...updatedHistory, modelTurn];
      setChatMessages(finalMessages);

      const computedTitle =
        chatMessages.length === 0 ? text.slice(0, 60) : chatTitle;
      setChatTitle(computedTitle);

      // Non-blocking Firestore persistence so chat display never fails if DB rules or network lag
      try {
        const savedId = await saveChatSession({
          chatId: activeChatId,
          userId: user.uid,
          title: computedTitle,
          rolePersona,
          modelName: data.modelUsed || selectedModel,
          messages: finalMessages,
        });
        setActiveChatId(savedId);
      } catch (persistErr) {
        console.warn('Non-fatal chat persistence warning:', persistErr);
      }
    } catch (err: unknown) {
      setChatError(err instanceof Error ? err.message : 'Failed to get chatbot response.');
    } finally {
      setChatSending(false);
    }
  };

  // ==========================================================================
  // 2. LIVE VOICE CONVERSATIONS (gemini-3.8-live via WebSocket)
  // ==========================================================================
  const [liveConnected, setLiveConnected] = useState(false);
  const [liveConnecting, setLiveConnecting] = useState(false);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [liveTranscripts, setLiveTranscripts] = useState<
    { speaker: 'Analyst' | 'SOC Live AI'; text: string }[]
  >([]);

  const wsRef = useRef<WebSocket | null>(null);
  const inputAudioCtxRef = useRef<AudioContext | null>(null);
  const outputAudioCtxRef = useRef<AudioContext | null>(null);
  const mediaStreamRef = useRef<MediaStream | null>(null);
  const processorRef = useRef<ScriptProcessorNode | null>(null);
  const nextStartTimeRef = useRef<number>(0);

  const stopLiveSession = () => {
    if (processorRef.current) {
      processorRef.current.disconnect();
      processorRef.current = null;
    }
    if (mediaStreamRef.current) {
      mediaStreamRef.current.getTracks().forEach((t) => t.stop());
      mediaStreamRef.current = null;
    }
    if (inputAudioCtxRef.current) {
      inputAudioCtxRef.current.close().catch(() => {});
      inputAudioCtxRef.current = null;
    }
    if (outputAudioCtxRef.current) {
      outputAudioCtxRef.current.close().catch(() => {});
      outputAudioCtxRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    nextStartTimeRef.current = 0;
    setLiveConnected(false);
    setLiveConnecting(false);
  };

  useEffect(() => {
    return () => {
      stopLiveSession();
    };
  }, []);

  const float32ToPcm16Base64 = (float32Array: Float32Array): string => {
    const int16Array = new Int16Array(float32Array.length);
    for (let i = 0; i < float32Array.length; i++) {
      const s = Math.max(-1, Math.min(1, float32Array[i]));
      int16Array[i] = s < 0 ? s * 0x8000 : s * 0x7fff;
    }
    const bytes = new Uint8Array(int16Array.buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  };

  const schedulePcm24kPlayback = (base64Audio: string) => {
    const outCtx = outputAudioCtxRef.current;
    if (!outCtx) return;

    const binary = atob(base64Audio);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const int16 = new Int16Array(bytes.buffer);
    const float32 = new Float32Array(int16.length);
    for (let i = 0; i < int16.length; i++) {
      float32[i] = int16[i] / 32768.0;
    }

    const audioBuffer = outCtx.createBuffer(1, float32.length, 24000);
    audioBuffer.copyToChannel(float32, 0);

    const source = outCtx.createBufferSource();
    source.buffer = audioBuffer;
    source.connect(outCtx.destination);

    const now = outCtx.currentTime;
    if (nextStartTimeRef.current < now) {
      nextStartTimeRef.current = now;
    }
    source.start(nextStartTimeRef.current);
    nextStartTimeRef.current += audioBuffer.duration;
  };

  const startLiveSession = async () => {
    setLiveError(null);
    setLiveConnecting(true);
    try {
      const token = await user.getIdToken();
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      mediaStreamRef.current = stream;

      const inputCtx = new AudioContext({ sampleRate: 16000 });
      const outputCtx = new AudioContext({ sampleRate: 24000 });
      inputAudioCtxRef.current = inputCtx;
      outputAudioCtxRef.current = outputCtx;
      nextStartTimeRef.current = outputCtx.currentTime;

      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProtocol}//${window.location.host}/api/live?token=${encodeURIComponent(
        token
      )}`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setLiveConnecting(false);
        setLiveConnected(true);

        const source = inputCtx.createMediaStreamSource(stream);
        const processor = inputCtx.createScriptProcessor(4096, 1, 1);
        processorRef.current = processor;

        processor.onaudioprocess = (e) => {
          if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
            const channelData = e.inputBuffer.getChannelData(0);
            const b64 = float32ToPcm16Base64(channelData);
            wsRef.current.send(JSON.stringify({ audio: b64 }));
          }
        };

        source.connect(processor);
        processor.connect(inputCtx.destination);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.error) {
            setLiveError(msg.error);
          }
          if (msg.audio) {
            schedulePcm24kPlayback(msg.audio);
          }
          if (msg.interrupted && outputAudioCtxRef.current) {
            nextStartTimeRef.current = outputAudioCtxRef.current.currentTime;
          }
          if (msg.inputTranscript) {
            setLiveTranscripts((prev) => [
              ...prev.slice(-15),
              { speaker: 'Analyst', text: msg.inputTranscript },
            ]);
          }
          if (msg.outputTranscript) {
            setLiveTranscripts((prev) => [
              ...prev.slice(-15),
              { speaker: 'SOC Live AI', text: msg.outputTranscript },
            ]);
          }
        } catch {
          // Ignore parse error
        }
      };

      ws.onerror = () => {
        setLiveError('WebSocket connection error with Live API.');
        stopLiveSession();
      };

      ws.onclose = () => {
        stopLiveSession();
      };
    } catch (err: unknown) {
      setLiveError(
        err instanceof Error
          ? err.message
          : 'Microphone access or Live session initialization failed.'
      );
      stopLiveSession();
    }
  };

  // ==========================================================================
  // 3. AUDIO TRANSCRIPTION (gemini-3.5-transcribe)
  // ==========================================================================
  const [recordingAudio, setRecordingAudio] = useState(false);
  const [transcribing, setTranscribing] = useState(false);
  const [transcriptResult, setTranscriptResult] = useState('');
  const [transcribeError, setTranscribeError] = useState<string | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recordedChunksRef = useRef<Blob[]>([]);

  const handleStartAudioRecording = async () => {
    setTranscribeError(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      recordedChunksRef.current = [];
      const recorder = new MediaRecorder(stream);
      mediaRecorderRef.current = recorder;

      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) {
          recordedChunksRef.current.push(e.data);
        }
      };

      recorder.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(recordedChunksRef.current, {
          type: recorder.mimeType || 'audio/webm',
        });
        await submitBlobForTranscription(blob, recorder.mimeType || 'audio/webm');
      };

      recorder.start();
      setRecordingAudio(true);
    } catch (err: unknown) {
      setTranscribeError(
        err instanceof Error ? err.message : 'Unable to access microphone for recording.'
      );
    }
  };

  const handleStopAudioRecording = () => {
    if (mediaRecorderRef.current && recordingAudio) {
      mediaRecorderRef.current.stop();
      setRecordingAudio(false);
    }
  };

  const submitBlobForTranscription = async (blob: Blob, mimeType: string) => {
    setTranscribing(true);
    setTranscribeError(null);
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
        }),
      });
      setTranscriptResult(res.transcript || 'No speech detected in audio.');
    } catch (err: unknown) {
      setTranscribeError(err instanceof Error ? err.message : 'Transcription failed.');
    } finally {
      setTranscribing(false);
    }
  };

  const handleAudioFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    await submitBlobForTranscription(file, file.type || 'audio/mp3');
  };

  // ==========================================================================
  // 4. GOOGLE SEARCH & GOOGLE MAPS GROUNDING
  // ==========================================================================
  const [groundingMode, setGroundingMode] = useState<'search' | 'maps'>('search');
  const [groundingQuery, setGroundingQuery] = useState('');
  const [groundingLat, setGroundingLat] = useState('');
  const [groundingLng, setGroundingLng] = useState('');
  const [groundingLoading, setGroundingLoading] = useState(false);
  const [groundingError, setGroundingError] = useState<string | null>(null);
  const [searchResult, setSearchResult] = useState<{
    text: string;
    sources: { uri: string; title: string }[];
  } | null>(null);
  const [mapsResult, setMapsResult] = useState<{
    text: string;
    places: { uri: string; title: string; reviewSnippets: string[] }[];
  } | null>(null);

  const handleUseBrowserGeolocation = () => {
    if (!navigator.geolocation) {
      setGroundingError('Browser geolocation is not supported.');
      return;
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setGroundingLat(pos.coords.latitude.toFixed(5));
        setGroundingLng(pos.coords.longitude.toFixed(5));
      },
      () => {
        setGroundingError('Could not retrieve current browser coordinates.');
      }
    );
  };

  const handleRunGrounding = async (e?: React.FormEvent, preset?: string) => {
    if (e) e.preventDefault();
    const q = (preset ?? groundingQuery).trim();
    if (!q) return;
    if (preset) setGroundingQuery(preset);

    setGroundingLoading(true);
    setGroundingError(null);
    try {
      if (groundingMode === 'search') {
        const res = await authenticatedFetch('/api/grounding/search', {
          method: 'POST',
          body: JSON.stringify({ query: q }),
        });
        setSearchResult(res);
      } else {
        const lat = groundingLat ? parseFloat(groundingLat) : undefined;
        const lng = groundingLng ? parseFloat(groundingLng) : undefined;
        const res = await authenticatedFetch('/api/grounding/maps', {
          method: 'POST',
          body: JSON.stringify({ query: q, latitude: lat, longitude: lng }),
        });
        setMapsResult(res);
      }
    } catch (err: unknown) {
      setGroundingError(err instanceof Error ? err.message : 'Grounding query failed.');
    } finally {
      setGroundingLoading(false);
    }
  };

  // ==========================================================================
  // 5. IMAGE STUDIO & VEO 3 VIDEO GENERATOR
  // ==========================================================================
  const [imagePrompt, setImagePrompt] = useState('');
  const [imageAspectRatio, setImageAspectRatio] = useState<
    '1:1' | '16:9' | '9:16' | '4:3' | '3:4'
  >('16:9');
  const [imageHighQuality, setImageHighQuality] = useState(false);
  const [uploadedEditImage, setUploadedEditImage] = useState<{
    base64: string;
    mimeType: string;
  } | null>(null);
  const [imageLoading, setImageLoading] = useState(false);
  const [imageError, setImageError] = useState<string | null>(null);
  const [generatedImage, setGeneratedImage] = useState<{
    imageUrl: string;
    caption: string;
    modelUsed: string;
  } | null>(null);

  const [videoPrompt, setVideoPrompt] = useState('');
  const [videoAspectRatio, setVideoAspectRatio] = useState<'16:9' | '9:16'>('16:9');
  const [videoLoading, setVideoLoading] = useState(false);
  const [videoStatusMsg, setVideoStatusMsg] = useState('');
  const [videoError, setVideoError] = useState<string | null>(null);
  const [generatedVideoUrl, setGeneratedVideoUrl] = useState<string | null>(null);

  const handleImageUploadForEdit = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onloadend = () => {
      setUploadedEditImage({
        base64: String(reader.result || ''),
        mimeType: file.type || 'image/png',
      });
    };
    reader.readAsDataURL(file);
  };

  const handleGenerateOrEditImage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!imagePrompt.trim()) return;
    setImageLoading(true);
    setImageError(null);
    try {
      const res = await authenticatedFetch('/api/image/generate', {
        method: 'POST',
        body: JSON.stringify({
          prompt: imagePrompt.trim(),
          aspectRatio: imageAspectRatio,
          highQuality: imageHighQuality,
          base64Image: uploadedEditImage?.base64,
          mimeType: uploadedEditImage?.mimeType,
        }),
      });
      setGeneratedImage(res);
    } catch (err: unknown) {
      setImageError(err instanceof Error ? err.message : 'Image generation failed.');
    } finally {
      setImageLoading(false);
    }
  };

  const handleGenerateVeoVideo = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!videoPrompt.trim() || videoLoading) return;
    setVideoLoading(true);
    setVideoError(null);
    setGeneratedVideoUrl(null);
    setVideoStatusMsg('Submitting prompt to Veo 3 (veo-3.1-lite-generate-preview)...');

    try {
      const startRes = await authenticatedFetch('/api/generate-video', {
        method: 'POST',
        body: JSON.stringify({
          prompt: videoPrompt.trim(),
          aspectRatio: videoAspectRatio,
        }),
      });

      const operationName = startRes.operationName;
      if (!operationName) {
        throw new Error('No operationName returned from video generation endpoint.');
      }

      setVideoStatusMsg('Rendering security briefing video (this may take 1-2 minutes)...');

      let done = false;
      for (let attempt = 0; attempt < 40; attempt++) {
        await new Promise((r) => setTimeout(r, 5000));
        const pollRes = await authenticatedFetch('/api/video-status', {
          method: 'POST',
          body: JSON.stringify({ operationName }),
        });
        if (pollRes.error) {
          throw new Error(pollRes.error);
        }
        if (pollRes.done) {
          done = true;
          break;
        }
        setVideoStatusMsg(
          `Synthesizing frames with Veo 3 (check ${attempt + 1})... Stay on this tab.`
        );
      }

      if (!done) {
        throw new Error('Video generation timed out. Please try again.');
      }

      setVideoStatusMsg('Downloading rendered MP4 stream via secure proxy...');
      const token = await user.getIdToken();
      const dlRes = await fetch('/api/video-download', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ operationName }),
      });

      if (!dlRes.ok) {
        const contentType = dlRes.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          const errJson = await dlRes.json().catch(() => ({}));
          const errMsg =
            typeof errJson?.error === 'string'
              ? errJson.error
              : errJson?.error?.message ||
                errJson?.message ||
                `Video download failed (${dlRes.status})`;
          throw new Error(errMsg);
        }
        throw new Error(
          'The analysis service returned an unexpected response. Please check the API endpoint and backend logs.'
        );
      }

      const videoBlob = await dlRes.blob();
      const objectUrl = URL.createObjectURL(videoBlob);
      setGeneratedVideoUrl(objectUrl);
      setVideoStatusMsg('');
    } catch (err: unknown) {
      setVideoError(err instanceof Error ? err.message : 'Veo 3 video generation failed.');
      setVideoStatusMsg('');
    } finally {
      setVideoLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Sub-Navigation Bar */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white font-display">
            Gemini AI Security Operations Center
          </h2>
          <p className="text-xs text-slate-400">
            Multi-turn SOC Chat, Live Voice API, Audio Transcription, Search & Maps Grounding, and
            Visual Briefing Studio.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
          {[
            { id: 'chat', label: 'SOC Chatbot', icon: <MessageSquare className="w-3.5 h-3.5" /> },
            { id: 'live-voice', label: 'Live Voice API', icon: <Radio className="w-3.5 h-3.5" /> },
            { id: 'transcribe', label: 'Transcribe Audio', icon: <Mic className="w-3.5 h-3.5" /> },
            {
              id: 'grounding',
              label: 'Search & Maps Grounding',
              icon: <Search className="w-3.5 h-3.5" />,
            },
            {
              id: 'media-studio',
              label: 'Image & Veo 3 Studio',
              icon: <ImageIcon className="w-3.5 h-3.5" />,
            },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id as SuiteTab)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md flex items-center gap-1.5 transition-colors cursor-pointer whitespace-nowrap ${
                activeTab === tab.id
                  ? 'bg-emerald-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* =================================================================== */}
      {/* TAB 1: MULTI-TURN GEMINI SOC CHATBOT                                */}
      {/* =================================================================== */}
      {activeTab === 'chat' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Saved Firestore Chat Threads & Role/Model Controls (4 cols) */}
          <div className="lg:col-span-4 bg-[#0b1325] border border-slate-800 rounded-xl p-5 space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-white">Configuration & Threads</h3>
              <button
                type="button"
                onClick={handleNewChat}
                className="px-2.5 py-1 text-xs font-medium bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg flex items-center gap-1 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>New Chat</span>
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="space-y-1">
                <label className="block font-medium text-slate-300">Gemini Model Tier</label>
                <select
                  value={selectedModel}
                  onChange={(e) => setSelectedModel(e.target.value as any)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-500"
                >
                  <option value="gemini-3.8-flash">
                    gemini-3.8-flash (General SOC Tasks & Google Search)
                  </option>
                  <option value="gemini-3.1-flash-lite">
                    gemini-3.1-flash-lite (Fast Tasks / Low Latency)
                  </option>
                  <option value="gemini-4-argon">
                    gemini-4-argon (Complex Multi-Step Tasks & Deep Reasoning)
                  </option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="block font-medium text-slate-300">System Role Persona</label>
                <select
                  value={rolePersona}
                  onChange={(e) => setRolePersona(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                >
                  <option value="soc-analyst">Lead SOC Threat Intelligence Analyst</option>
                  <option value="incident-responder">Incident Response Commander</option>
                  <option value="dns-architect">Email & DNS Hardening Architect</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="block font-medium text-slate-300">
                  Attach Recent Scan Telemetry (Optional)
                </label>
                <select
                  value={attachedScanId}
                  onChange={(e) => setAttachedScanId(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-500"
                >
                  <option value="">None (General / Tool-Assisted Chat)</option>
                  {recentScans.slice(0, 15).map((s) => (
                    <option key={s.scanId} value={s.scanId}>
                      [{s.scanType.toUpperCase()}] {s.target.slice(0, 32)} ({s.riskScore}/100)
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-2 pt-1">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableSecurityTools}
                    onChange={(e) => setEnableSecurityTools(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-500"
                  />
                  <span className="text-slate-300 font-medium">
                    Auto-Run Live URL / IP / Message Scanners
                  </span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={chatSearchGrounding}
                    onChange={(e) => setChatSearchGrounding(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-500"
                  />
                  <span className="text-slate-300 font-medium">
                    Enable Google Search Grounding
                  </span>
                </label>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 space-y-2">
              <p className="text-xs font-semibold text-slate-300">
                Saved Conversations ({chatSessions.length})
              </p>
              {chatSessions.length === 0 ? (
                <p className="text-xs text-slate-500 py-4">
                  Your multi-turn conversations are automatically saved to Firestore.
                </p>
              ) : (
                <div className="divide-y divide-slate-800 max-h-[240px] overflow-y-auto border border-slate-800 rounded-lg">
                  {chatSessions.map((s) => (
                    <div
                      key={s.chatId}
                      onClick={() => handleSelectSavedChat(s)}
                      className={`p-3 cursor-pointer flex items-center justify-between gap-2 transition-colors ${
                        activeChatId === s.chatId ? 'bg-emerald-950/40 text-emerald-300' : 'hover:bg-slate-900/60'
                      }`}
                    >
                      <div className="min-w-0">
                        <p className="text-xs font-medium text-slate-200 truncate">{s.title}</p>
                        <p className="text-[11px] font-mono text-slate-500 truncate">
                          {s.modelName} · {s.messages?.length || 0} msgs
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteChatSession(s.chatId);
                          if (activeChatId === s.chatId) handleNewChat();
                        }}
                        className="text-slate-500 hover:text-rose-400 p-1 cursor-pointer"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Right: Scrollable Multi-Turn Conversation Thread (8 cols) */}
          <div className="lg:col-span-8 bg-[#0b1325] border border-slate-800 rounded-xl flex flex-col h-[620px] overflow-hidden">
            <div className="px-5 py-3.5 border-b border-slate-800 bg-[#070d19] flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs text-slate-300">
                <Sparkles className="w-4 h-4 text-emerald-400" />
                <span className="font-semibold text-white">{chatTitle}</span>
                <span>·</span>
                <span className="font-mono text-slate-400">{selectedModel}</span>
              </div>
              <span className="text-xs text-slate-400 font-mono tabular-nums">
                {chatMessages.length} turns
              </span>
            </div>

            <div
              ref={chatScrollRef}
              className="flex-1 p-5 overflow-y-auto space-y-4 bg-[#030712]"
            >
              {chatMessages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center max-w-lg mx-auto space-y-4">
                  <div className="w-10 h-10 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-emerald-400">
                    <Sparkles className="w-5 h-5" />
                  </div>
                  <div className="space-y-1">
                    <p className="text-sm font-semibold text-white">
                      Gemini AI Security Assistant & Live Tool Copilot
                    </p>
                    <p className="text-xs text-slate-400">
                      Ask Gemini to execute live URL/Domain, Public IP, or Message phishing scans
                      automatically via Function Calling, or investigate DNS, RDAP, and incident
                      response playbooks.
                    </p>
                  </div>
                  <div className="flex flex-wrap justify-center gap-2">
                    {[
                      'Scan https://github.com/login and summarize its DNS, RDAP age, and TLS status.',
                      'Scan IP 1.1.1.1 and check its ASN, PTR, and DNSBL abuse status.',
                      'How do I configure strict DMARC p=reject with SPF and DKIM?',
                      'Explain how attackers abuse IDN Punycode homographs in phishing.',
                    ].map((q) => (
                      <button
                        key={q}
                        type="button"
                        onClick={() => handleSendChatMessage(undefined, q)}
                        className="px-3 py-1.5 text-xs bg-slate-900 hover:bg-slate-800 hover:border-emerald-500/50 text-slate-300 border border-slate-800 rounded-lg cursor-pointer text-left transition-colors"
                      >
                        {q}
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                chatMessages.map((msg, i) => (
                  <div
                    key={i}
                    className={`flex flex-col ${
                      msg.role === 'user' ? 'items-end' : 'items-start'
                    }`}
                  >
                    <div
                      className={`max-w-[88%] rounded-xl p-3.5 text-xs leading-relaxed whitespace-pre-wrap ${
                        msg.role === 'user'
                          ? 'bg-emerald-600 text-white rounded-tr-none'
                          : 'bg-[#0b1325] border border-slate-800 text-slate-200 shadow-md rounded-tl-none'
                      }`}
                    >
                      {Array.isArray(msg.executedTools) && msg.executedTools.length > 0 && (
                        <div className="mb-3 pb-2.5 border-b border-slate-800 space-y-2">
                          <p className="text-[11px] font-mono font-semibold text-emerald-400">
                            Executed Live Security Tool Telemetry:
                          </p>
                          {msg.executedTools.map((t, tIdx) => (
                            <div
                              key={tIdx}
                              className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 font-mono text-[11px] space-y-1"
                            >
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-semibold text-white">
                                  {t.toolName} → {t.target}
                                </span>
                                <span className="text-emerald-400 font-semibold tabular-nums">
                                  {t.verdict} ({t.riskScore}/100)
                                </span>
                              </div>
                              <p className="text-slate-400">{t.summary}</p>
                            </div>
                          ))}
                        </div>
                      )}

                      <div>{msg.text}</div>

                      {msg.role === 'model' && (
                        <div className="mt-3 pt-2 border-t border-slate-800 flex items-center justify-between gap-2">
                          <span className="text-[10px] font-mono text-slate-500">
                            Gemini Security Assistant
                          </span>
                          <button
                            type="button"
                            disabled={ttsLoadingIdx === i}
                            onClick={() => handlePlayMessageTts(msg.text, i)}
                            className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-400 hover:text-emerald-300 cursor-pointer"
                          >
                            <Volume2 className="w-3.5 h-3.5" />
                            <span>
                              {ttsLoadingIdx === i
                                ? 'Synthesizing Audio...'
                                : ttsPlayingIdx === i
                                  ? 'Stop Audio'
                                  : 'Listen (TTS)'}
                            </span>
                          </button>
                        </div>
                      )}

                      {Array.isArray(msg.sources) && msg.sources.length > 0 && (
                        <div className="mt-3 pt-2.5 border-t border-slate-800 space-y-1">
                          <p className="text-[11px] font-semibold text-slate-400">
                            Google Search Grounded Sources:
                          </p>
                          <div className="flex flex-wrap gap-2">
                            {msg.sources.map((src, idx) => (
                              <a
                                key={idx}
                                href={src.uri}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-[11px] text-emerald-400 hover:underline font-mono"
                              >
                                <span>{src.title}</span>
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ))
              )}

              {chatSending && (
                <div className="text-xs text-slate-400 font-mono flex items-center gap-2">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-emerald-400" />
                  <span>
                    {selectedModel} is analyzing (running live security tools & grounding)...
                  </span>
                </div>
              )}
            </div>

            {chatError && (
              <div className="px-5 py-2.5 bg-rose-950/80 border-t border-rose-800 text-xs text-rose-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{chatError}</span>
              </div>
            )}

            <form
              onSubmit={(e) => handleSendChatMessage(e)}
              className="p-4 border-t border-slate-800 bg-[#070d19] flex items-center gap-3"
            >
              <input
                type="text"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder="Ask a follow-up question about threat indicators, DNS, or remediation..."
                className="flex-1 px-3.5 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <button
                type="submit"
                disabled={chatSending || !chatInput.trim()}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Send</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 2: REAL-TIME VOICE CONVERSATIONS (gemini-3.8-live)              */}
      {/* =================================================================== */}
      {/* =================================================================== */}
      {/* TAB 2: REAL-TIME VOICE CONVERSATIONS (gemini-3.8-live)              */}
      {/* =================================================================== */}
      {activeTab === 'live-voice' && (
        <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="space-y-1">
              <h3 className="text-base font-bold text-white font-display">
                Real-Time Voice SOC Analyst (gemini-3.8-live)
              </h3>
              <p className="text-xs text-slate-400">
                Low-latency bidirectional voice conversation over WebSocket using 16kHz PCM mic
                streaming and 24kHz gapless scheduled audio output.
              </p>
            </div>

            <div className="flex items-center gap-3">
              {!liveConnected ? (
                <button
                  type="button"
                  disabled={liveConnecting}
                  onClick={startLiveSession}
                  className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center gap-2 cursor-pointer whitespace-nowrap"
                >
                  <Mic className="w-4 h-4" />
                  <span>
                    {liveConnecting ? 'Connecting to gemini-3.8-live...' : 'Start Live Voice Session'}
                  </span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={stopLiveSession}
                  className="px-5 py-2.5 bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold rounded-lg flex items-center gap-2 cursor-pointer whitespace-nowrap"
                >
                  <MicOff className="w-4 h-4" />
                  <span>End Live Voice Session</span>
                </button>
              )}
            </div>
          </div>

          {liveError && (
            <div className="p-3.5 rounded-lg bg-rose-950/80 border border-rose-800 text-xs text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{liveError}</span>
            </div>
          )}

          <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col items-center justify-center text-center space-y-3">
            <div
              className={`w-14 h-14 rounded-full flex items-center justify-center border ${
                liveConnected
                  ? 'bg-emerald-950/80 border-emerald-500 text-emerald-400 animate-pulse'
                  : 'bg-slate-900 border-slate-800 text-slate-500'
              }`}
            >
              <Volume2 className="w-6 h-6" />
            </div>
            <p className="text-sm font-semibold text-white">
              {liveConnected
                ? 'Live Voice Bridge Active — Speak naturally into your microphone'
                : 'Click "Start Live Voice Session" to talk with the Live SOC Analyst'}
            </p>
            <p className="text-xs text-slate-400 font-mono">
              Model: gemini-3.8-live · Input: 16kHz PCM · Output: 24kHz PCM (Zephyr Voice)
            </p>
          </div>

          {liveTranscripts.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold text-slate-300">Live Session Transcripts:</p>
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-2 max-h-60 overflow-y-auto text-xs">
                {liveTranscripts.map((item, idx) => (
                  <div key={idx} className="flex items-start gap-2">
                    <span className="font-mono font-semibold text-white shrink-0">
                      {item.speaker}:
                    </span>
                    <span className="text-slate-300">{item.text}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 3: AUDIO TRANSCRIPTION (gemini-3.5-transcribe)                  */}
      {/* =================================================================== */}
      {activeTab === 'transcribe' && (
        <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="border-b border-slate-800 pb-4 space-y-1">
            <h3 className="text-base font-bold text-white font-display">
              Vishing & Security Audio Transcription (gemini-3.5-transcribe)
            </h3>
            <p className="text-xs text-slate-400">
              Record a voice note with your microphone or upload a suspicious voicemail/audio clip
              to transcribe it with <code className="font-mono text-emerald-400">gemini-3.5-transcribe</code>.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            {!recordingAudio ? (
              <button
                type="button"
                disabled={transcribing}
                onClick={handleStartAudioRecording}
                className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center gap-2 cursor-pointer whitespace-nowrap"
              >
                <Mic className="w-4 h-4" />
                <span>Record Microphone Audio</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={handleStopAudioRecording}
                className="px-5 py-2.5 bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold rounded-lg flex items-center gap-2 cursor-pointer whitespace-nowrap animate-pulse"
              >
                <MicOff className="w-4 h-4" />
                <span>Stop Recording & Transcribe</span>
              </button>
            )}

            <label className="px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-medium rounded-lg flex items-center gap-2 cursor-pointer whitespace-nowrap">
              <Upload className="w-4 h-4" />
              <span>Upload Audio File (.mp3 / .wav / .webm)</span>
              <input
                type="file"
                accept="audio/*"
                onChange={handleAudioFileUpload}
                className="hidden"
              />
            </label>
          </div>

          {transcribing && (
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-300 font-mono flex items-center gap-2">
              <RefreshCw className="w-4 h-4 animate-spin text-emerald-400" />
              <span>Transcribing audio via gemini-3.5-transcribe...</span>
            </div>
          )}

          {transcribeError && (
            <div className="p-3.5 rounded-lg bg-rose-950/80 border border-rose-800 text-xs text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{transcribeError}</span>
            </div>
          )}

          {transcriptResult && (
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between">
                <p className="text-xs font-semibold text-slate-300">
                  Transcription Output (gemini-3.5-transcribe):
                </p>
                {onSendTranscriptToMessageScanner && (
                  <button
                    type="button"
                    onClick={() => onSendTranscriptToMessageScanner(transcriptResult)}
                    className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white border border-slate-700 text-xs font-medium rounded-lg flex items-center gap-1.5 cursor-pointer"
                  >
                    <span>Inspect Transcript in Message Phishing Scanner</span>
                    <ArrowRight className="w-3.5 h-3.5 text-emerald-400" />
                  </button>
                )}
              </div>
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg text-sm text-slate-200 leading-relaxed whitespace-pre-wrap">
                {transcriptResult}
              </div>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 4: GOOGLE SEARCH & GOOGLE MAPS GROUNDING                        */}
      {/* =================================================================== */}
      {activeTab === 'grounding' && (
        <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="space-y-1">
              <h3 className="text-base font-bold text-white font-display">
                Real-Time Google Search & Google Maps Grounding
              </h3>
              <p className="text-xs text-slate-400">
                Retrieve up-to-date threat advisories with <code className="font-mono text-emerald-400">googleSearch</code>{' '}
                or locate physical CERT/SOC response facilities with{' '}
                <code className="font-mono text-emerald-400">googleMaps</code>.
              </p>
            </div>

            <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
              <button
                type="button"
                onClick={() => setGroundingMode('search')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md flex items-center gap-1.5 cursor-pointer ${
                  groundingMode === 'search'
                    ? 'bg-emerald-600 text-white shadow-xs'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Search className="w-3.5 h-3.5" />
                <span>Google Search Grounding</span>
              </button>
              <button
                type="button"
                onClick={() => setGroundingMode('maps')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md flex items-center gap-1.5 cursor-pointer ${
                  groundingMode === 'maps'
                    ? 'bg-emerald-600 text-white shadow-xs'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <MapPin className="w-3.5 h-3.5" />
                <span>Google Maps Grounding</span>
              </button>
            </div>
          </div>

          <form onSubmit={(e) => handleRunGrounding(e)} className="space-y-4">
            {groundingMode === 'maps' && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <input
                  type="text"
                  value={groundingLat}
                  onChange={(e) => setGroundingLat(e.target.value)}
                  placeholder="Latitude (optional, e.g. 37.78193)"
                  className="px-3 py-2 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-white"
                />
                <input
                  type="text"
                  value={groundingLng}
                  onChange={(e) => setGroundingLng(e.target.value)}
                  placeholder="Longitude (optional, e.g. -122.40476)"
                  className="px-3 py-2 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-white"
                />
                <button
                  type="button"
                  onClick={handleUseBrowserGeolocation}
                  className="px-3 py-2 text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded-lg cursor-pointer"
                >
                  Use My Current Location
                </button>
              </div>
            )}

            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                required
                value={groundingQuery}
                onChange={(e) => setGroundingQuery(e.target.value)}
                placeholder={
                  groundingMode === 'search'
                    ? 'Search live CVEs, recent phishing campaigns, or CISA advisories...'
                    : 'Locate cybersecurity incident response offices, data centers, or law enforcement offices...'
                }
                className="flex-1 px-3.5 py-2.5 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <button
                type="submit"
                disabled={groundingLoading}
                className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-xs font-semibold rounded-lg cursor-pointer whitespace-nowrap"
              >
                {groundingLoading
                  ? 'Querying Grounding Engine...'
                  : groundingMode === 'search'
                    ? 'Search Live Web'
                    : 'Query Google Maps'}
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-400">Quick Queries:</span>
              {groundingMode === 'search'
                ? [
                    'Latest CISA phishing and credential harvesting advisories',
                    'Recent AiTM (Adversary-in-the-Middle) phishing techniques',
                  ].map((preset) => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => handleRunGrounding(undefined, preset)}
                      className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-md text-[11px] cursor-pointer"
                    >
                      {preset}
                    </button>
                  ))
                : [
                    'Cybersecurity offices and data centers in San Francisco, CA',
                    'FBI Field Offices and cyber crime reporting hubs in New York',
                  ].map((preset) => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => handleRunGrounding(undefined, preset)}
                      className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-md text-[11px] cursor-pointer"
                    >
                      {preset}
                    </button>
                  ))}
            </div>
          </form>

          {groundingError && (
            <div className="p-3.5 rounded-lg bg-rose-950/80 border border-rose-800 text-xs text-rose-300">
              {groundingError}
            </div>
          )}

          {groundingMode === 'search' && searchResult && (
            <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
              <div className="text-sm text-slate-200 leading-relaxed whitespace-pre-wrap">
                {searchResult.text}
              </div>

              {searchResult.sources.length > 0 && (
                <div className="pt-3 border-t border-slate-800 space-y-2">
                  <p className="text-xs font-semibold text-white">
                    Verified Web Grounding Citations ({searchResult.sources.length}):
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {searchResult.sources.map((src, i) => (
                      <a
                        key={i}
                        href={src.uri}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg hover:border-emerald-500 transition-colors flex items-center justify-between gap-2 text-xs text-emerald-400 font-medium"
                      >
                        <span className="truncate">{src.title}</span>
                        <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {groundingMode === 'maps' && mapsResult && (
            <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
              <div className="text-sm text-slate-200 leading-relaxed whitespace-pre-wrap">
                {mapsResult.text}
              </div>

              {mapsResult.places.length > 0 && (
                <div className="pt-3 border-t border-slate-800 space-y-3">
                  <p className="text-xs font-semibold text-white">
                    Google Maps Grounded Locations ({mapsResult.places.length}):
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {mapsResult.places.map((pl, i) => (
                      <div
                        key={i}
                        className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2"
                      >
                        <a
                          href={pl.uri}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 hover:underline"
                        >
                          <MapPin className="w-3.5 h-3.5 shrink-0" />
                          <span>{pl.title}</span>
                          <ExternalLink className="w-3 h-3 shrink-0" />
                        </a>
                        {pl.reviewSnippets.length > 0 && (
                          <div className="space-y-1 text-[11px] text-slate-400">
                            {pl.reviewSnippets.map((snip, sIdx) => (
                              <p key={sIdx} className="italic">
                                “{snip}”
                              </p>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 5: IMAGE CREATION/EDITING & VEO 3 VIDEO GENERATOR               */}
      {/* =================================================================== */}
      {activeTab === 'media-studio' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Create & Edit Images (6 cols) */}
          <div className="lg:col-span-6 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-5">
            <div className="border-b border-slate-800 pb-3 space-y-1">
              <div className="flex items-center gap-2">
                <ImageIcon className="w-4 h-4 text-emerald-400" />
                <h3 className="text-base font-bold text-white font-display">
                  Create & Edit Security Visuals
                </h3>
              </div>
              <p className="text-xs text-slate-400">
                Generate or edit threat topology visuals using{' '}
                <code className="font-mono text-emerald-400">gemini-3.1-flash-lite-image</code> or{' '}
                <code className="font-mono text-emerald-400">gemini-3.1-flash-image</code>.
              </p>
            </div>

            <form onSubmit={handleGenerateOrEditImage} className="space-y-4 text-xs">
              <div className="space-y-1.5">
                <label className="block font-medium text-slate-300">
                  Image Generation or Editing Prompt
                </label>
                <textarea
                  rows={3}
                  required
                  value={imagePrompt}
                  onChange={(e) => setImagePrompt(e.target.value)}
                  placeholder="e.g., Clean technical diagram of zero-trust email authentication with SPF, DKIM, and DMARC shields on a dark cybersecurity SOC canvas"
                  className="w-full p-3 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="block font-medium text-slate-300">Aspect Ratio</label>
                  <select
                    value={imageAspectRatio}
                    onChange={(e) => setImageAspectRatio(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                  >
                    <option value="16:9">16:9 (Landscape)</option>
                    <option value="1:1">1:1 (Square)</option>
                    <option value="4:3">4:3 (Standard)</option>
                    <option value="3:4">3:4 (Portrait)</option>
                    <option value="9:16">9:16 (Vertical)</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="block font-medium text-slate-300">Reference Image (Edit)</label>
                  <label className="w-full px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg text-slate-300 flex items-center justify-center gap-1.5 cursor-pointer">
                    <Upload className="w-3.5 h-3.5" />
                    <span className="truncate">
                      {uploadedEditImage ? 'Image Attached (Click to change)' : 'Upload to Edit'}
                    </span>
                    <input
                      type="file"
                      accept="image/*"
                      onChange={handleImageUploadForEdit}
                      className="hidden"
                    />
                  </label>
                </div>
              </div>

              <div className="flex items-center justify-between pt-1">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={imageHighQuality}
                    onChange={(e) => setImageHighQuality(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-emerald-500"
                  />
                  <span className="text-slate-300">
                    Use gemini-3.1-flash-image (1K High-Quality)
                  </span>
                </label>

                {uploadedEditImage && (
                  <button
                    type="button"
                    onClick={() => setUploadedEditImage(null)}
                    className="text-rose-400 hover:underline cursor-pointer"
                  >
                    Clear Edit Image
                  </button>
                )}
              </div>

              <button
                type="submit"
                disabled={imageLoading}
                className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white font-semibold rounded-lg cursor-pointer"
              >
                {imageLoading
                  ? 'Rendering Image...'
                  : uploadedEditImage
                    ? 'Edit Image with Prompt'
                    : 'Generate Image'}
              </button>
            </form>

            {imageError && (
              <div className="p-3 rounded-lg bg-rose-950/80 border border-rose-800 text-xs text-rose-300">
                {imageError}
              </div>
            )}

            {generatedImage && (
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <img
                  src={generatedImage.imageUrl}
                  alt="Generated cybersecurity asset"
                  referrerPolicy="no-referrer"
                  className="w-full rounded-lg border border-slate-800"
                />
                <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                  <span>Model: {generatedImage.modelUsed}</span>
                  <button
                    type="button"
                    onClick={() =>
                      setUploadedEditImage({
                        base64: generatedImage.imageUrl,
                        mimeType: 'image/png',
                      })
                    }
                    className="text-emerald-400 hover:underline cursor-pointer"
                  >
                    Use this image for further editing
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Right: Veo 3 Video Generation (6 cols) */}
          <div className="lg:col-span-6 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-5">
            <div className="border-b border-slate-800 pb-3 space-y-1">
              <div className="flex items-center gap-2">
                <Video className="w-4 h-4 text-emerald-400" />
                <h3 className="text-base font-bold text-white font-display">
                  Veo 3 Security Briefing Video Generator
                </h3>
              </div>
              <p className="text-xs text-slate-400">
                Generate 720p landscape (<code className="font-mono text-emerald-400">16:9</code>) or portrait (
                <code className="font-mono text-emerald-400">9:16</code>) videos using{' '}
                <code className="font-mono text-emerald-400">veo-3.1-lite-generate-preview</code>.
              </p>
            </div>

            <form onSubmit={handleGenerateVeoVideo} className="space-y-4 text-xs">
              <div className="space-y-1.5">
                <label className="block font-medium text-slate-300">Video Prompt</label>
                <textarea
                  rows={3}
                  required
                  value={videoPrompt}
                  onChange={(e) => setVideoPrompt(e.target.value)}
                  placeholder="e.g., Cinematic visualization of an optical firewall intercepting malicious phishing packets in a modern cybersecurity operations center"
                  className="w-full p-3 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="space-y-1">
                <label className="block font-medium text-slate-300">Video Aspect Ratio</label>
                <div className="grid grid-cols-2 gap-3">
                  {(['16:9', '9:16'] as const).map((ratio) => (
                    <button
                      key={ratio}
                      type="button"
                      onClick={() => setVideoAspectRatio(ratio)}
                      className={`py-2 px-3 rounded-lg border font-mono text-xs cursor-pointer ${
                        videoAspectRatio === ratio
                          ? 'bg-emerald-600 text-white border-emerald-500'
                          : 'bg-slate-950 text-slate-300 border-slate-800 hover:bg-slate-900'
                      }`}
                    >
                      {ratio === '16:9' ? '16:9 Landscape' : '9:16 Portrait'}
                    </button>
                  ))}
                </div>
              </div>

              <button
                type="submit"
                disabled={videoLoading}
                className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white font-semibold rounded-lg cursor-pointer"
              >
                {videoLoading ? 'Generating Video with Veo 3...' : 'Generate Veo 3 Video'}
              </button>
            </form>

            {videoStatusMsg && (
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-300 font-mono flex items-center gap-2">
                <RefreshCw className="w-4 h-4 animate-spin text-emerald-400 shrink-0" />
                <span>{videoStatusMsg}</span>
              </div>
            )}

            {videoError && (
              <div className="p-3 rounded-lg bg-rose-950/80 border border-rose-800 text-xs text-rose-300">
                {videoError}
              </div>
            )}

            {generatedVideoUrl && (
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <video
                  src={generatedVideoUrl}
                  controls
                  className="w-full rounded-lg border border-slate-800 bg-black"
                />
                <p className="text-[11px] font-mono text-slate-500">
                  Rendered via veo-3.1-lite-generate-preview ({videoAspectRatio})
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

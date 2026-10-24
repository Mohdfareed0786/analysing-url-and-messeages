import React, { useState, useEffect, useRef } from 'react';
import {
  Mic,
  MicOff,
  Radio,
  Volume2,
  VolumeX,
  Sparkles,
  PhoneCall,
  PhoneOff,
  Send,
  Copy,
  Check,
  RotateCcw,
  Shield,
  ShieldAlert,
  AlertTriangle,
  ArrowRight,
  Info,
  Layers,
  ChevronDown,
  X,
  ExternalLink,
} from 'lucide-react';
import { auth } from '../lib/firebase';

export type VoicePersona = 'Zephyr' | 'Puck' | 'Charon' | 'Kore' | 'Fenrir';

interface LiveVoiceAssistantProps {
  initialTopic?: string | null;
  onCloseModal?: () => void;
  isModal?: boolean;
  onSendTranscriptToMessageScanner?: (transcript: string) => void;
}

interface TranscriptItem {
  id: string;
  speaker: 'Analyst' | 'SOC Live AI';
  text: string;
  timestamp: string;
}

export const LiveVoiceAssistant: React.FC<LiveVoiceAssistantProps> = ({
  initialTopic,
  onCloseModal,
  isModal = false,
  onSendTranscriptToMessageScanner,
}) => {
  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [muted, setMuted] = useState(false);
  const [voice, setVoice] = useState<VoicePersona>('Zephyr');
  const [error, setError] = useState<string | null>(null);
  const [transcripts, setTranscripts] = useState<TranscriptItem[]>([]);
  const [textInput, setTextInput] = useState('');
  const [copied, setCopied] = useState(false);
  const [audioLevel, setAudioLevel] = useState<number>(0);
  const [aiSpeaking, setAiSpeaking] = useState<boolean>(false);

  // Audio Context & WebSocket Refs
  const wsRef = useRef<WebSocket | null>(null);
  const inputAudioCtxRef = useRef<AudioContext | null>(null);
  const outputAudioCtxRef = useRef<AudioContext | null>(null);
  const mediaStreamRef = useRef<MediaStream | null>(null);
  const processorRef = useRef<ScriptProcessorNode | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const animFrameRef = useRef<number | null>(null);
  const nextStartTimeRef = useRef<number>(0);
  const transcriptsEndRef = useRef<HTMLDivElement | null>(null);

  // Auto-scroll transcripts
  useEffect(() => {
    transcriptsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [transcripts]);

  // Cleanup on unmount
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

    try {
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

      setAiSpeaking(true);
      setTimeout(() => {
        if (outputAudioCtxRef.current && nextStartTimeRef.current <= outputAudioCtxRef.current.currentTime) {
          setAiSpeaking(false);
        }
      }, audioBuffer.duration * 1000);
    } catch {
      // Audio playback buffer error
    }
  };

  const stopLiveSession = () => {
    if (animFrameRef.current) {
      cancelAnimationFrame(animFrameRef.current);
      animFrameRef.current = null;
    }
    if (processorRef.current) {
      processorRef.current.disconnect();
      processorRef.current = null;
    }
    if (analyserRef.current) {
      analyserRef.current.disconnect();
      analyserRef.current = null;
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
    setConnected(false);
    setConnecting(false);
    setAudioLevel(0);
    setAiSpeaking(false);
  };

  const startLiveSession = async () => {
    setError(null);
    setConnecting(true);

    try {
      const user = auth.currentUser;
      if (!user) {
        throw new Error('Please sign in to start a real-time Gemini Live voice conversation.');
      }

      const token = await user.getIdToken();

      // Request mic stream (16kHz standard for Gemini Live)
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          channelCount: 1,
          sampleRate: 16000,
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
        },
      });
      mediaStreamRef.current = stream;

      const inputCtx = new (window.AudioContext || (window as any).webkitAudioContext)({
        sampleRate: 16000,
      });
      inputAudioCtxRef.current = inputCtx;

      const outputCtx = new (window.AudioContext || (window as any).webkitAudioContext)({
        sampleRate: 24000,
      });
      outputAudioCtxRef.current = outputCtx;
      nextStartTimeRef.current = outputCtx.currentTime;

      // Audio Level Analyser for Live Waveform Visualizer
      const analyser = inputCtx.createAnalyser();
      analyser.fftSize = 64;
      analyserRef.current = analyser;

      const source = inputCtx.createMediaStreamSource(stream);
      source.connect(analyser);

      const dataArray = new Uint8Array(analyser.frequencyBinCount);
      const updateMeter = () => {
        if (!analyserRef.current) return;
        analyserRef.current.getByteFrequencyData(dataArray);
        let sum = 0;
        for (let i = 0; i < dataArray.length; i++) {
          sum += dataArray[i];
        }
        const avg = sum / dataArray.length;
        setAudioLevel(Math.min(100, Math.round((avg / 128) * 100)));
        animFrameRef.current = requestAnimationFrame(updateMeter);
      };
      updateMeter();

      // Connect to WebSocket /api/live with auth token, voice, and optional topic
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      let wsUrl = `${wsProtocol}//${window.location.host}/api/live?token=${encodeURIComponent(token)}&voice=${encodeURIComponent(voice)}`;
      if (initialTopic) {
        wsUrl += `&topic=${encodeURIComponent(initialTopic)}`;
      }

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnecting(false);
        setConnected(true);

        const processor = inputCtx.createScriptProcessor(4096, 1, 1);
        processorRef.current = processor;

        processor.onaudioprocess = (e) => {
          if (muted) return;
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
            setError(msg.error);
          }
          if (msg.audio) {
            schedulePcm24kPlayback(msg.audio);
          }
          if (msg.interrupted && outputAudioCtxRef.current) {
            nextStartTimeRef.current = outputAudioCtxRef.current.currentTime;
            setAiSpeaking(false);
          }
          if (msg.inputTranscript) {
            setTranscripts((prev) => [
              ...prev,
              {
                id: `in_${Date.now()}_${Math.random()}`,
                speaker: 'Analyst',
                text: msg.inputTranscript,
                timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
              },
            ]);
          }
          if (msg.outputTranscript) {
            setTranscripts((prev) => [
              ...prev,
              {
                id: `out_${Date.now()}_${Math.random()}`,
                speaker: 'SOC Live AI',
                text: msg.outputTranscript,
                timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
              },
            ]);
          }
        } catch {
          // Parse error
        }
      };

      ws.onerror = () => {
        setError('Connection to Gemini Live WebSocket encountered an error.');
        stopLiveSession();
      };

      ws.onclose = () => {
        stopLiveSession();
      };
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to access microphone or connect to Gemini 3.8 Live.'
      );
      stopLiveSession();
    }
  };

  const handleSendTextMessage = () => {
    if (!textInput.trim() || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    const text = textInput.trim();
    wsRef.current.send(JSON.stringify({ text }));
    setTranscripts((prev) => [
      ...prev,
      {
        id: `text_${Date.now()}`,
        speaker: 'Analyst',
        text,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      },
    ]);
    setTextInput('');
  };

  const handlePromptStarter = (promptText: string) => {
    if (!connected) {
      startLiveSession().then(() => {
        setTimeout(() => {
          if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify({ text: promptText }));
            setTranscripts((prev) => [
              ...prev,
              {
                id: `starter_${Date.now()}`,
                speaker: 'Analyst',
                text: promptText,
                timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
              },
            ]);
          }
        }, 1200);
      });
    } else if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ text: promptText }));
      setTranscripts((prev) => [
        ...prev,
        {
          id: `starter_${Date.now()}`,
          speaker: 'Analyst',
          text: promptText,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    }
  };

  const handleCopyTranscript = () => {
    if (transcripts.length === 0) return;
    const text = transcripts.map((t) => `[${t.timestamp}] ${t.speaker}: ${t.text}`).join('\n\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const promptStarters = [
    { label: 'Triage URL: http://neverssl.com', text: 'Triage URL http://neverssl.com: What are the risks of unencrypted HTTP protocols, and how do attackers exploit cleartext transport?' },
    { label: 'Urgent Wire Scam Email', text: 'Analyze this scenario: An employee received an urgent email from the CEO asking to wire $45,000 to an updated bank account. How do we verify this spear-phishing attack?' },
    { label: 'Explain DNSBL Blacklists', text: 'Explain DNSBL blacklists such as Spamhaus ZEN and Barracuda. What does it mean if an IP is listed on a reputation blocklist?' },
    { label: 'Compromised Password Guidance', text: 'A user accidentally entered their Google credentials on a lookalike login page 5 minutes ago. What immediate containment steps should our SOC take?' },
  ];

  return (
    <div className={`bg-[#0b1325] border border-slate-800 rounded-xl shadow-xl overflow-hidden flex flex-col ${isModal ? 'h-full max-h-[90vh]' : 'space-y-6 p-6'}`}>
      {/* 1. Header Banner */}
      <div className={`border-b border-slate-800 bg-[#070d19] text-white flex flex-col md:flex-row md:items-center justify-between gap-4 ${isModal ? 'p-4' : 'p-6 rounded-t-xl'}`}>
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md border border-emerald-500/30">
              <Radio className={`w-4 h-4 ${connected ? 'animate-pulse text-emerald-400' : 'text-slate-400'}`} />
            </span>
            <h2 className="text-lg font-bold font-display tracking-tight text-white flex items-center gap-2">
              Gemini Live Voice SOC Analyst
              <span className="text-[10px] font-mono uppercase bg-emerald-950 text-emerald-400 px-2 py-0.5 rounded border border-emerald-800">
                gemini-3.8-live
              </span>
            </h2>
          </div>
          <p className="text-xs text-slate-300">
            Bidirectional real-time voice conversation over WebSocket with native 16kHz audio capture, 24kHz audio synthesis, and live speech transcription.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Voice Persona Selector */}
          <div className="flex items-center gap-1.5 bg-slate-800/90 border border-slate-700 rounded-md px-2.5 py-1 text-xs">
            <Volume2 className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={voice}
              onChange={(e) => setVoice(e.target.value as VoicePersona)}
              disabled={connected || connecting}
              className="bg-transparent text-slate-200 font-medium text-xs focus:outline-none cursor-pointer disabled:opacity-50"
              title="Select Gemini Voice Persona"
            >
              <option value="Zephyr" className="bg-slate-900 text-white">Voice: Zephyr (Balanced)</option>
              <option value="Kore" className="bg-slate-900 text-white">Voice: Kore (Composed)</option>
              <option value="Puck" className="bg-slate-900 text-white">Voice: Puck (Energetic)</option>
              <option value="Fenrir" className="bg-slate-900 text-white">Voice: Fenrir (Authoritative)</option>
              <option value="Charon" className="bg-slate-900 text-white">Voice: Charon (Calm)</option>
            </select>
          </div>

          {/* Close Modal Button if rendered inside a dialog */}
          {onCloseModal && (
            <button
              type="button"
              onClick={onCloseModal}
              className="p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
              title="Close Voice Assistant"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* 2. Interactive Voice Studio Console */}
      <div className={`grid grid-cols-1 lg:grid-cols-12 gap-6 ${isModal ? 'p-4 overflow-y-auto flex-1' : ''}`}>
        {/* Left Column: Visualizer, Status & Call Controls */}
        <div className="lg:col-span-5 space-y-5">
          {/* Audio Visualizer Orb Card */}
          <div className="bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border border-slate-800 rounded-xl p-6 text-center space-y-5 relative overflow-hidden shadow-inner">
            {/* Visualizer Pulsing Ring */}
            <div
              className={`relative flex items-center justify-center my-4 ${!connected ? 'cursor-pointer group' : ''}`}
              onClick={!connected ? startLiveSession : undefined}
              title={!connected ? 'Click to Start Voice Session' : undefined}
            >
              <div
                className={`w-32 h-32 rounded-full flex items-center justify-center transition-all duration-300 ${
                  connected
                    ? aiSpeaking
                      ? 'bg-rose-500/20 ring-8 ring-rose-500/30'
                      : audioLevel > 15
                        ? 'bg-emerald-500/20 ring-8 ring-emerald-500/30'
                        : 'bg-emerald-500/10 ring-4 ring-emerald-500/20'
                    : 'bg-slate-800/80 ring-2 ring-emerald-500/30 hover:ring-emerald-500/60 hover:scale-105'
                }`}
              >
                <div
                  className={`w-20 h-20 rounded-full flex items-center justify-center transition-transform duration-150 ${
                    connected
                      ? aiSpeaking
                        ? 'bg-rose-600 scale-105 shadow-lg shadow-rose-900/50'
                        : audioLevel > 15
                          ? 'bg-emerald-600 scale-110 shadow-lg shadow-emerald-900/50'
                          : 'bg-emerald-700 shadow-md shadow-emerald-950'
                      : 'bg-emerald-600 group-hover:bg-emerald-500 shadow-lg shadow-emerald-950/60'
                  }`}
                >
                  {connected ? (
                    aiSpeaking ? (
                      <Volume2 className="w-8 h-8 text-white animate-pulse" />
                    ) : (
                      <Mic className="w-8 h-8 text-white" />
                    )
                  ) : (
                    <Mic className="w-8 h-8 text-white group-hover:scale-110 transition-transform" />
                  )}
                </div>
              </div>

              {/* Dynamic Wave Bars */}
              {connected && (
                <div className="absolute -bottom-2 flex items-center justify-center gap-1.5 h-6">
                  {[20, 50, 80, 100, 70, 40, 90, 60].map((heightPct, idx) => {
                    const scaled = Math.max(15, (audioLevel * heightPct) / 100);
                    return (
                      <span
                        key={idx}
                        className={`w-1 rounded-full transition-all duration-75 ${
                          aiSpeaking ? 'bg-rose-400' : 'bg-emerald-400'
                        }`}
                        style={{ height: `${scaled}%` }}
                      />
                    );
                  })}
                </div>
              )}
            </div>

            {/* Connection Status Label */}
            <div className="space-y-1">
              <div className="flex items-center justify-center gap-2 text-xs font-mono">
                <span
                  className={`w-2.5 h-2.5 rounded-full ${
                    connected
                      ? aiSpeaking
                        ? 'bg-rose-500 animate-ping'
                        : 'bg-emerald-500 animate-pulse'
                      : connecting
                        ? 'bg-amber-400 animate-pulse'
                        : 'bg-emerald-400 animate-ping'
                  }`}
                />
                <span className="font-semibold text-white">
                  {connected
                    ? aiSpeaking
                      ? 'SOC AI Speaking (Barge-in enabled)...'
                      : muted
                        ? 'Microphone Muted'
                        : 'Live & Listening (Speak anytime)...'
                    : connecting
                      ? 'Connecting to Gemini 3.8 Live...'
                      : 'Voice Session Ready (Click to Speak)'}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                {connected
                  ? `Voice: ${voice} · Full-duplex audio stream (16kHz in / 24kHz out)`
                  : 'Tap the microphone orb or click Start Voice Session below to talk'}
              </p>
            </div>

            {/* Primary Action Buttons */}
            <div className="flex items-center justify-center gap-3 pt-2">
              {!connected ? (
                <button
                  type="button"
                  onClick={startLiveSession}
                  disabled={connecting}
                  className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 active:scale-95 disabled:opacity-50 text-white font-semibold rounded-lg text-xs flex items-center gap-2 shadow-lg shadow-emerald-950/50 transition-all cursor-pointer font-sans"
                >
                  <PhoneCall className="w-4 h-4 text-white" />
                  <span>{connecting ? 'Connecting...' : 'Start Voice Session'}</span>
                </button>
              ) : (
                <>
                  <button
                    type="button"
                    onClick={() => setMuted(!muted)}
                    className={`px-3 py-2 rounded-lg text-xs font-medium border flex items-center gap-1.5 transition-colors cursor-pointer ${
                      muted
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                        : 'bg-slate-800 text-slate-200 border-slate-700 hover:bg-slate-700'
                    }`}
                    title={muted ? 'Unmute microphone' : 'Mute microphone'}
                  >
                    {muted ? <MicOff className="w-4 h-4 text-amber-400" /> : <Mic className="w-4 h-4" />}
                    <span>{muted ? 'Muted' : 'Mute'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={stopLiveSession}
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white font-medium rounded-lg text-xs flex items-center gap-1.5 shadow-sm transition-all cursor-pointer"
                  >
                    <PhoneOff className="w-4 h-4" />
                    <span>End Voice Call</span>
                  </button>
                </>
              )}
            </div>

            {error && (
              <div className="p-3 bg-red-950/80 border border-red-800 rounded-md text-red-200 text-xs text-left flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}
          </div>

          {/* Quick Scenario Starters */}
          <div className="border border-slate-800 rounded-xl p-4 bg-slate-900/60 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                Voice Triage Starters
              </span>
              <span className="text-[10px] text-slate-500">Click to ask</span>
            </div>
            <div className="space-y-1.5">
              {promptStarters.map((starter, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handlePromptStarter(starter.text)}
                  className="w-full text-left p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 hover:border-emerald-500 hover:bg-slate-900 transition-all text-xs text-slate-300 flex items-center justify-between group cursor-pointer"
                >
                  <span className="font-medium group-hover:text-emerald-300 truncate pr-2">
                    {starter.label}
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-emerald-400 shrink-0" />
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Live Transcript Stream & Text Fallback */}
        <div className="lg:col-span-7 flex flex-col h-full min-h-[420px] border border-slate-800 rounded-xl overflow-hidden bg-[#070d19]">
          {/* Transcript Stream Header */}
          <div className="p-3 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span className="text-xs font-bold text-white font-display">
                Real-Time Speech & Audio Transcript Ledger
              </span>
            </div>

            <div className="flex items-center gap-2">
              {transcripts.length > 0 && (
                <>
                  <button
                    type="button"
                    onClick={handleCopyTranscript}
                    className="p-1 px-2 text-[11px] font-medium text-slate-300 hover:text-white bg-slate-800 border border-slate-700 rounded flex items-center gap-1 cursor-pointer"
                    title="Copy full conversation transcript"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>

                  {onSendTranscriptToMessageScanner && (
                    <button
                      type="button"
                      onClick={() => {
                        const fullText = transcripts
                          .filter((t) => t.speaker === 'Analyst')
                          .map((t) => t.text)
                          .join('\n');
                        onSendTranscriptToMessageScanner(fullText);
                      }}
                      className="p-1 px-2 text-[11px] font-medium text-emerald-300 hover:bg-emerald-950/40 bg-slate-800 border border-emerald-700 rounded flex items-center gap-1 cursor-pointer"
                      title="Send analyst transcript to Message NLP Scanner"
                    >
                      <ExternalLink className="w-3 h-3 text-emerald-400" />
                      <span>Scan as Message</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => setTranscripts([])}
                    className="p-1 text-slate-400 hover:text-white cursor-pointer"
                    title="Clear transcript"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Transcript Scroll Area */}
          <div className="flex-1 p-4 overflow-y-auto space-y-3 bg-[#030712] min-h-[300px] max-h-[460px]">
            {transcripts.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-8 space-y-3">
                <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400">
                  <Mic className="w-6 h-6 text-slate-500" />
                </div>
                <div className="space-y-1 max-w-sm">
                  <p className="text-sm font-semibold text-white">No voice conversation active</p>
                  <p className="text-xs text-slate-400">
                    Click <strong className="text-slate-300">Start Voice Session</strong> to speak into your microphone, or click a <strong className="text-slate-300">Voice Triage Starter</strong> above. Real-time spoken dialogue and audio transcripts will appear here.
                  </p>
                </div>
              </div>
            ) : (
              transcripts.map((item) => (
                <div
                  key={item.id}
                  className={`flex flex-col ${item.speaker === 'Analyst' ? 'items-end' : 'items-start'}`}
                >
                  <div className="flex items-center gap-1.5 text-[10px] text-slate-400 px-1 mb-0.5">
                    <span className="font-semibold text-slate-300">{item.speaker}</span>
                    <span>•</span>
                    <span>{item.timestamp}</span>
                  </div>
                  <div
                    className={`max-w-[85%] rounded-lg px-3.5 py-2 text-xs leading-relaxed ${
                      item.speaker === 'Analyst'
                        ? 'bg-emerald-600 text-white rounded-tr-none'
                        : 'bg-[#0b1325] text-slate-200 border border-slate-800 shadow-lg rounded-tl-none'
                    }`}
                  >
                    {item.text}
                  </div>
                </div>
              ))
            )}
            <div ref={transcriptsEndRef} />
          </div>

          {/* Text Input Fallback */}
          <div className="p-3 bg-slate-900/90 border-t border-slate-800 flex items-center gap-2">
            <input
              type="text"
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleSendTextMessage();
              }}
              placeholder={connected ? "Type message to speak into Live session..." : "Connect voice first or click a starter above..."}
              disabled={!connected}
              className="flex-1 text-xs bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 disabled:opacity-50"
            />
            <button
              type="button"
              onClick={handleSendTextMessage}
              disabled={!connected || !textInput.trim()}
              className="px-3 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-40 text-white rounded-md text-xs font-medium cursor-pointer transition-colors"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

import React, { useState, useRef } from 'react';
import {
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendPasswordResetEmail,
  RecaptchaVerifier,
  signInWithPhoneNumber,
  ConfirmationResult,
  updateProfile,
} from 'firebase/auth';
import {
  Shield,
  Mail,
  Phone,
  Lock,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  KeyRound,
} from 'lucide-react';
import { auth, googleProvider } from '../lib/firebase';
import firebaseConfig from '../../firebase-applet-config.json';
import topologyAsset from '../assets/images/threat_ops_topology_1791350492534.jpg';

type AuthTab = 'google' | 'email' | 'phone';
type EmailMode = 'signin' | 'signup' | 'reset';

export const AuthGate: React.FC = () => {
  const [activeTab, setActiveTab] = useState<AuthTab>('google');
  const [emailMode, setEmailMode] = useState<EmailMode>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [confirmationResult, setConfirmationResult] = useState<ConfirmationResult | null>(null);

  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [providerSetupGuide, setProviderSetupGuide] = useState<'email' | 'phone' | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [imgLoaded, setImgLoaded] = useState(true);

  const recaptchaVerifierRef = useRef<RecaptchaVerifier | null>(null);

  const clearFeedback = () => {
    setErrorMsg(null);
    setProviderSetupGuide(null);
    setStatusMessage(null);
  };

  const handleGoogleLogin = async () => {
    clearFeedback();
    setLoading(true);
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      const message = err instanceof Error ? err.message : 'Google authentication failed.';
      if (code === 'auth/popup-closed-by-user') {
        setErrorMsg('Sign-in popup was closed before completing authentication.');
      } else {
        setErrorMsg(message);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleEmailAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    clearFeedback();
    if (!email.trim()) {
      setErrorMsg('Please enter your email address.');
      return;
    }

    setLoading(true);
    try {
      if (emailMode === 'reset') {
        await sendPasswordResetEmail(auth, email.trim());
        setStatusMessage(
          `Password reset instructions have been sent to ${email.trim()}. Check your inbox.`
        );
        setLoading(false);
        return;
      }

      if (password.length < 6) {
        setErrorMsg('Password must be at least 6 characters.');
        setLoading(false);
        return;
      }

      if (emailMode === 'signup') {
        const cred = await createUserWithEmailAndPassword(auth, email.trim(), password);
        if (displayName.trim()) {
          await updateProfile(cred.user, { displayName: displayName.trim().slice(0, 80) });
        }
      } else {
        await signInWithEmailAndPassword(auth, email.trim(), password);
      }
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      if (code === 'auth/operation-not-allowed' || code === 'auth/configuration-not-found') {
        setProviderSetupGuide('email');
        setErrorMsg(
          'Email/Password sign-in is not yet enabled in your Firebase project console.'
        );
      } else if (code === 'auth/invalid-credential' || code === 'auth/wrong-password') {
        setErrorMsg('Invalid email or password. Please verify your credentials.');
      } else if (code === 'auth/email-already-in-use') {
        setErrorMsg('An account with this email already exists. Switch to Sign In.');
      } else {
        setErrorMsg(err instanceof Error ? err.message : 'Email authentication failed.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSendPhoneOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    clearFeedback();
    const formattedPhone = phoneNumber.trim();
    if (!/^\+[1-9]\d{6,14}$/.test(formattedPhone)) {
      setErrorMsg('Enter phone number in E.164 international format (e.g. +14155552671).');
      return;
    }

    setLoading(true);
    try {
      if (!recaptchaVerifierRef.current) {
        recaptchaVerifierRef.current = new RecaptchaVerifier(auth, 'recaptcha-container', {
          size: 'invisible',
        });
      }
      const confirmation = await signInWithPhoneNumber(
        auth,
        formattedPhone,
        recaptchaVerifierRef.current
      );
      setConfirmationResult(confirmation);
      setStatusMessage(`SMS verification code sent to ${formattedPhone}.`);
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      if (code === 'auth/operation-not-allowed' || code === 'auth/configuration-not-found') {
        setProviderSetupGuide('phone');
        setErrorMsg('Phone OTP sign-in is not yet enabled in your Firebase project console.');
      } else {
        setErrorMsg(err instanceof Error ? err.message : 'Failed to send SMS OTP.');
      }
      if (recaptchaVerifierRef.current) {
        recaptchaVerifierRef.current.clear();
        recaptchaVerifierRef.current = null;
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    clearFeedback();
    if (!confirmationResult || !otpCode.trim()) {
      setErrorMsg('Please enter the 6-digit verification code.');
      return;
    }

    setLoading(true);
    try {
      await confirmationResult.confirm(otpCode.trim());
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Invalid OTP verification code.');
    } finally {
      setLoading(false);
    }
  };

  const consoleAuthUrl = `https://console.firebase.google.com/project/${firebaseConfig.projectId}/authentication/providers`;

  return (
    <div className="min-h-screen bg-white text-slate-900 flex flex-col">
      {/* Top Bar Contract: 3 Zones (Single-element Brand, 4-5 Nav Links, 1 Primary Action) */}
      <header className="flex items-center justify-between px-6 lg:px-10 py-4 border-b border-slate-200 bg-white/95 sticky top-0 z-30">
        <a href="#top" className="text-lg font-bold tracking-tight text-slate-900 font-display">
          Phishing Shield
        </a>

        <nav className="hidden md:flex items-center gap-7 text-sm font-medium text-slate-600">
          <a href="#capabilities" className="hover:text-slate-900 transition-colors whitespace-nowrap">
            URL & Domain Engine
          </a>
          <a href="#capabilities" className="hover:text-slate-900 transition-colors whitespace-nowrap">
            RDAP & DNS Telemetry
          </a>
          <a href="#capabilities" className="hover:text-slate-900 transition-colors whitespace-nowrap">
            IP Reputation
          </a>
          <a href="#capabilities" className="hover:text-slate-900 transition-colors whitespace-nowrap">
            Gemini AI SOC Suite
          </a>
        </nav>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleGoogleLogin}
            disabled={loading}
            className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors whitespace-nowrap cursor-pointer"
          >
            Analyst Sign In
          </button>
        </div>
      </header>

      {/* Main Split Viewport */}
      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 lg:px-10 py-10 lg:py-16 grid grid-cols-1 lg:grid-cols-12 gap-12 items-start">
        {/* Left Column: Product Architecture & Live Telemetry Overview (7 cols) */}
        <div className="lg:col-span-7 space-y-8" id="capabilities">
          <div className="space-y-4">
            <p className="text-xs font-mono text-emerald-700 font-semibold tracking-wide">
              Detect. Analyze. Protect. · Zero-Simulation Security Inspection
            </p>
            <h1 className="text-3xl sm:text-4xl lg:text-[42px] font-bold tracking-tight text-slate-900 leading-[1.15] font-display max-w-2xl">
              Deterministic Phishing & Infrastructure Threat Analysis.
            </h1>
            <p className="text-base text-slate-600 leading-relaxed max-w-[65ch]">
              Phishing Shield executes live DNS resolution, authoritative RDAP domain registration
              queries, TLS X.509 certificate handshakes, multi-zone DNSBL IP blackhole lookups,
              Abuse.ch URLhaus checks, and Gemini AI multi-turn threat investigation.
            </p>
          </div>

          {/* Visual Topology Asset with Resilient Fallback */}
          <div className="relative rounded-lg overflow-hidden border border-slate-200 bg-slate-900">
            {imgLoaded ? (
              <div className="relative aspect-video w-full overflow-hidden">
                <img
                  src={topologyAsset}
                  alt="Phishing Shield optical network inspection topology"
                  referrerPolicy="no-referrer"
                  onError={() => setImgLoaded(false)}
                  className="w-full h-full object-cover object-center opacity-90"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-slate-950/90 via-slate-950/40 to-transparent flex flex-col justify-end p-6">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4 border-t border-white/15">
                    <div>
                      <p className="text-xs text-slate-300">DNS & Mail Auth</p>
                      <p className="text-sm font-mono font-semibold text-white tabular-nums mt-0.5">
                        A · MX · SPF · DMARC
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-300">Registration Age</p>
                      <p className="text-sm font-mono font-semibold text-white tabular-nums mt-0.5">
                        Live IANA RDAP
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-300">IP Reputation</p>
                      <p className="text-sm font-mono font-semibold text-white tabular-nums mt-0.5">
                        ASN · PTR · 4x DNSBL
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-300">Gemini AI SOC</p>
                      <p className="text-sm font-mono font-semibold text-white tabular-nums mt-0.5">
                        Chat · Live Voice · Veo
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 bg-slate-50 flex items-center gap-4">
                <Shield className="w-10 h-10 text-emerald-600 shrink-0" />
                <div>
                  <h3 className="text-base font-semibold text-slate-900">
                    Multi-Layer Security Inspection Pipeline
                  </h3>
                  <p className="text-sm text-slate-600">
                    Real-time URL, Domain, RDAP, DNS, Public IP, and Gemini AI SOC analysis.
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* 3 Architectural Pillars — Whitespace & Hairline Dividers */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 pt-4 border-t border-slate-200">
            <div className="space-y-1.5">
              <h3 className="text-sm font-semibold text-slate-900">01. Evidence-Backed Scoring</h3>
              <p className="text-xs text-slate-600 leading-relaxed">
                Every risk score point is linked to a verifiable technical signal. Domain age is
                evaluated as context and never triggers a false positive alone.
              </p>
            </div>
            <div className="space-y-1.5">
              <h3 className="text-sm font-semibold text-slate-900">02. Integrated Gemini AI SOC</h3>
              <p className="text-xs text-slate-600 leading-relaxed">
                Includes Multi-Turn SOC Chatbot, Live Voice Conversations, Audio Transcription,
                Google Search & Maps Grounding, and Visual Briefing Studio.
              </p>
            </div>
            <div className="space-y-1.5">
              <h3 className="text-sm font-semibold text-slate-900">03. Isolated Tenant Storage</h3>
              <p className="text-xs text-slate-600 leading-relaxed">
                Authenticated via JWT session verification. Scan history, incident reports, and chat
                sessions are strictly isolated per user UID.
              </p>
            </div>
          </div>
        </div>

        {/* Right Column: Authentication Console (5 cols) */}
        <div className="lg:col-span-5 bg-slate-50 border border-slate-200 rounded-lg p-6 sm:p-8 space-y-6">
          <div className="space-y-1">
            <h2 className="text-xl font-bold text-slate-900 font-display">
              Analyst Workspace Authentication
            </h2>
            <p className="text-xs text-slate-600">
              Sign in to access live security scanners, Gemini AI Assistant, scan history, and reports.
            </p>
          </div>

          {/* Interactive Auth Method Selector */}
          <div className="grid grid-cols-3 gap-1 p-1 bg-slate-200/70 border border-slate-200 rounded-md">
            <button
              type="button"
              onClick={() => {
                setActiveTab('google');
                clearFeedback();
              }}
              className={`px-3 py-2 text-xs font-medium rounded transition-colors whitespace-nowrap cursor-pointer ${
                activeTab === 'google'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Google OAuth
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveTab('email');
                clearFeedback();
              }}
              className={`px-3 py-2 text-xs font-medium rounded transition-colors whitespace-nowrap cursor-pointer ${
                activeTab === 'email'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Email + Password
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveTab('phone');
                clearFeedback();
              }}
              className={`px-3 py-2 text-xs font-medium rounded transition-colors whitespace-nowrap cursor-pointer ${
                activeTab === 'phone'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Phone OTP
            </button>
          </div>

          {/* Feedback Banners */}
          {errorMsg && (
            <div className="p-3.5 rounded-md bg-red-50 border border-red-200 text-xs text-red-800 space-y-2">
              <div className="flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                <span>{errorMsg}</span>
              </div>
              {providerSetupGuide && (
                <div className="pt-2 border-t border-red-200 text-slate-700 space-y-1.5">
                  <p className="font-semibold text-slate-900">
                    How to enable {providerSetupGuide === 'email' ? 'Email/Password' : 'Phone OTP'}{' '}
                    in Firebase Console:
                  </p>
                  <ol className="list-decimal list-inside space-y-1 text-[11px] text-slate-600">
                    <li>Open your Firebase Authentication Sign-in providers page.</li>
                    <li>
                      Click{' '}
                      <strong>
                        {providerSetupGuide === 'email' ? 'Email/Password' : 'Phone'}
                      </strong>{' '}
                      and toggle <strong>Enable</strong>, then click Save.
                    </li>
                    <li>
                      Or click <strong>Google OAuth</strong> above for immediate zero-config sign-in.
                    </li>
                  </ol>
                  <a
                    href={consoleAuthUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-emerald-700 hover:underline font-medium pt-1"
                  >
                    <span>Open Firebase Auth Console ({firebaseConfig.projectId})</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
              )}
            </div>
          )}

          {statusMessage && (
            <div className="p-3.5 rounded-md bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
              <span>{statusMessage}</span>
            </div>
          )}

          {/* Tab 1: Continue with Google */}
          {activeTab === 'google' && (
            <div className="space-y-5 pt-2">
              <p className="text-xs text-slate-600 leading-relaxed">
                Authenticate via Google OAuth 2.0 / OpenID Connect. Your session issues a signed JWT
                verified on every API request by the Phishing Shield backend.
              </p>

              <button
                type="button"
                onClick={handleGoogleLogin}
                disabled={loading}
                className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white font-semibold text-sm rounded-md transition-colors flex items-center justify-center gap-2.5 cursor-pointer whitespace-nowrap"
              >
                <Shield className="w-4 h-4" />
                <span>{loading ? 'Authenticating Session...' : 'Continue with Google'}</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              <div className="pt-4 border-t border-slate-200 text-xs text-slate-500 space-y-1">
                <p className="font-medium text-slate-700">Session Security Specification</p>
                <p className="font-mono text-[11px] text-slate-500">
                  OAuth 2.0 Popup Flow · Bearer ID Token Verification · Per-UID Firestore Isolation
                </p>
              </div>
            </div>
          )}

          {/* Tab 2: Email + Password & Password Reset */}
          {activeTab === 'email' && (
            <form onSubmit={handleEmailAuth} className="space-y-4">
              <div className="flex items-center justify-between text-xs text-slate-600 pb-1 border-b border-slate-200">
                <span>
                  {emailMode === 'signin'
                    ? 'Sign in with Email & Password'
                    : emailMode === 'signup'
                      ? 'Register New Analyst Account'
                      : 'Reset Account Password'}
                </span>
                <div className="flex items-center gap-3">
                  {emailMode !== 'signin' && (
                    <button
                      type="button"
                      onClick={() => {
                        setEmailMode('signin');
                        clearFeedback();
                      }}
                      className="text-emerald-700 font-medium hover:underline cursor-pointer"
                    >
                      Sign In
                    </button>
                  )}
                  {emailMode !== 'signup' && (
                    <button
                      type="button"
                      onClick={() => {
                        setEmailMode('signup');
                        clearFeedback();
                      }}
                      className="text-emerald-700 font-medium hover:underline cursor-pointer"
                    >
                      Create Account
                    </button>
                  )}
                </div>
              </div>

              {emailMode === 'signup' && (
                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-slate-700">
                    Analyst Display Name
                  </label>
                  <input
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="e.g. Alex Rivera"
                    maxLength={80}
                    className="w-full px-3.5 py-2 text-sm bg-white border border-slate-300 rounded-md text-slate-900 placeholder-slate-400 focus:outline-none focus:border-emerald-600"
                  />
                </div>
              )}

              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-700">Email Address</label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-2.5" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@organization.com"
                    className="w-full pl-10 pr-3.5 py-2 text-sm bg-white border border-slate-300 rounded-md text-slate-900 placeholder-slate-400 focus:outline-none focus:border-emerald-600"
                  />
                </div>
              </div>

              {emailMode !== 'reset' && (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label className="block text-xs font-medium text-slate-700">Password</label>
                    {emailMode === 'signin' && (
                      <button
                        type="button"
                        onClick={() => {
                          setEmailMode('reset');
                          clearFeedback();
                        }}
                        className="text-[11px] text-slate-500 hover:text-emerald-700 cursor-pointer"
                      >
                        Forgot password?
                      </button>
                    )}
                  </div>
                  <div className="relative">
                    <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-2.5" />
                    <input
                      type="password"
                      required
                      minLength={6}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••"
                      className="w-full pl-10 pr-3.5 py-2 text-sm bg-white border border-slate-300 rounded-md text-slate-900 placeholder-slate-400 focus:outline-none focus:border-emerald-600"
                    />
                  </div>
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white font-semibold text-sm rounded-md transition-colors flex items-center justify-center gap-2 cursor-pointer whitespace-nowrap"
              >
                <KeyRound className="w-4 h-4" />
                <span>
                  {loading
                    ? 'Processing...'
                    : emailMode === 'signin'
                      ? 'Sign In with Email'
                      : emailMode === 'signup'
                        ? 'Create Analyst Account'
                        : 'Send Password Reset Email'}
                </span>
              </button>
            </form>
          )}

          {/* Tab 3: Phone Number + OTP */}
          {activeTab === 'phone' && (
            <div className="space-y-4">
              {!confirmationResult ? (
                <form onSubmit={handleSendPhoneOtp} className="space-y-4">
                  <div className="space-y-1.5">
                    <label className="block text-xs font-medium text-slate-700">
                      Phone Number (E.164 Format)
                    </label>
                    <div className="relative">
                      <Phone className="w-4 h-4 text-slate-400 absolute left-3.5 top-2.5" />
                      <input
                        type="tel"
                        required
                        value={phoneNumber}
                        onChange={(e) => setPhoneNumber(e.target.value)}
                        placeholder="+14155552671"
                        className="w-full pl-10 pr-3.5 py-2 text-sm font-mono bg-white border border-slate-300 rounded-md text-slate-900 placeholder-slate-400 focus:outline-none focus:border-emerald-600"
                      />
                    </div>
                    <p className="text-[11px] text-slate-500">
                      Include country code prefix (e.g., +1 for US/CA, +44 for UK, +91 for IN).
                    </p>
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white font-semibold text-sm rounded-md transition-colors flex items-center justify-center gap-2 cursor-pointer whitespace-nowrap"
                  >
                    <Phone className="w-4 h-4" />
                    <span>{loading ? 'Sending SMS OTP...' : 'Send One-Time Passcode'}</span>
                  </button>
                </form>
              ) : (
                <form onSubmit={handleVerifyOtp} className="space-y-4">
                  <div className="space-y-1.5">
                    <label className="block text-xs font-medium text-slate-700">
                      6-Digit SMS Verification Code
                    </label>
                    <input
                      type="text"
                      required
                      maxLength={6}
                      value={otpCode}
                      onChange={(e) => setOtpCode(e.target.value)}
                      placeholder="123456"
                      className="w-full px-3.5 py-2 text-base font-mono tracking-widest bg-white border border-slate-300 rounded-md text-slate-900 placeholder-slate-400 focus:outline-none focus:border-emerald-600 tabular-nums"
                    />
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      type="submit"
                      disabled={loading}
                      className="flex-1 py-2.5 px-4 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white font-semibold text-sm rounded-md transition-colors cursor-pointer whitespace-nowrap"
                    >
                      {loading ? 'Verifying...' : 'Verify OTP & Sign In'}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setConfirmationResult(null);
                        setOtpCode('');
                        clearFeedback();
                      }}
                      className="py-2.5 px-3 text-xs text-slate-600 hover:text-slate-900 border border-slate-300 rounded-md cursor-pointer whitespace-nowrap"
                    >
                      Change Phone
                    </button>
                  </div>
                </form>
              )}
              <div id="recaptcha-container" />
            </div>
          )}
        </div>
      </main>

      {/* Quiet Footer */}
      <footer className="mt-auto border-t border-slate-200 px-6 lg:px-10 py-5 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-3 bg-slate-50">
        <span>Phishing Shield · Enterprise Threat Analysis Platform</span>
        <span>Zero-Trust Session Verification · Live DNS, RDAP, DNSBL & Gemini AI</span>
      </footer>
    </div>
  );
};

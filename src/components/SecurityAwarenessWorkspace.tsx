import React, { useState } from 'react';
import {
  GraduationCap,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Award,
  RefreshCw,
  ArrowRight,
  BookOpen,
  Lock,
  Globe,
  MessageSquareWarning,
  QrCode,
} from 'lucide-react';

interface QuizQuestion {
  id: number;
  category: 'URL & Homographs' | 'Message & Social Engineering' | 'Quishing & QR Scams' | 'Credential Harvesting';
  scenario: string;
  question: string;
  options: string[];
  correctIndex: number;
  explanation: string;
  redFlags: string[];
}

const QUIZ_QUESTIONS: QuizQuestion[] = [
  {
    id: 1,
    category: 'URL & Homographs',
    scenario: 'You receive an email asking you to verify your banking credentials at: "https://paypaI-secure-login.com/account/auth"',
    question: 'Why is this domain highly suspicious even though it uses https://?',
    options: [
      'HTTPS cannot protect passwords anyway.',
      'The domain uses typosquatting / homoglyph substitution (capital "I" instead of "l") and is not the official paypal.com domain.',
      'All domains ending with -secure-login.com are automatically blocked by ICANN.',
      'The URL contains too many slashes in the path.',
    ],
    correctIndex: 1,
    explanation: 'Attackers frequently register lookalike domains using typosquatting or homoglyphs (such as uppercase I in place of lowercase l) combined with security buzzwords like "-secure-login" to deceive users. HTTPS only encrypts the connection to the attacker\'s server—it does not verify whether the server is legitimate!',
    redFlags: ['Substituted homoglyph character', 'Domain not owned by PayPal', 'HTTPS used merely as false legitimacy badge'],
  },
  {
    id: 2,
    category: 'Message & Social Engineering',
    scenario: 'SMS: "URGENT: Your electricity connection will be disconnected tonight at 9:30 PM due to unpaid bill #99214. Call our verification executive immediately at 98765-XXXXX or pay via UPI: powerdesk@paytm to avoid power cutoff."',
    question: 'Which primary social engineering technique is being deployed in this message?',
    options: [
      'Zero-day exploit delivery',
      'Artificial urgency & intimidation to bypass critical thinking and force immediate unverified payment',
      'Denial of Service (DoS)',
      'Man-in-the-Middle credential interception',
    ],
    correctIndex: 1,
    explanation: 'Scammers rely heavily on artificial deadlines (e.g. "tonight at 9:30 PM") and threatening consequences (power cutoff, bank account freeze) to induce panic. Legitimate utilities send formal paper notices and never ask for immediate payments to personal UPI IDs.',
    redFlags: ['Artificial immediate deadline', 'Intimidation / account cutoff threat', 'Direct payment to personal UPI handle'],
  },
  {
    id: 3,
    category: 'Quishing & QR Scams',
    scenario: 'You see a paper QR code sticker placed directly over the official parking meter pay station with text reading "Quick Pay Meter - Scan to Pay Parking Fee".',
    question: 'What is the primary danger associated with scanning this QR sticker?',
    options: [
      'QR codes can physically fry your camera sensor.',
      'Attackers paste malicious QR stickers (quishing) over legitimate physical meters to redirect you to credential harvesters or fraudulent payment gateways.',
      'Scanning QR codes automatically deducts money without user confirmation.',
      'QR codes can only be scanned by authorized law enforcement apps.',
    ],
    correctIndex: 1,
    explanation: 'Quishing (QR phishing) often uses physical overlay stickers placed on parking meters, restaurant tables, or electric vehicle chargers. When scanned, they open fake payment pages that steal your card details while your real parking goes unpaid.',
    redFlags: ['Physical sticker pasted over existing signage', 'No domain preview before payment', 'Publicly accessible unverified surface'],
  },
  {
    id: 4,
    category: 'Credential Harvesting',
    scenario: 'An email from "IT Support" with sender address "it-helpdesk@company-internal-support.xyz" says: "Quarterly Microsoft 365 password audit required. Log in to keep your mailbox active."',
    question: 'What should an analyst inspect first before clicking any link in this email?',
    options: [
      'The font size of the email text.',
      'The sender domain alignment (is it the company\'s official corporate domain or a newly registered .xyz lookalike?).',
      'Whether the email has an image attached.',
      'How fast the email loaded in the mail client.',
    ],
    correctIndex: 1,
    explanation: 'Always inspect sender domain alignment. Legitimate internal IT departments only email from your company\'s verified internal domain name, never from third-party generic TLDs like .xyz or .top registered by outside entities.',
    redFlags: ['Mismatch between corporate identity and sender domain', 'Routine password audit lure', 'Threat of mailbox deactivation'],
  },
];

export const SecurityAwarenessWorkspace: React.FC = () => {
  const [selectedAnswers, setSelectedAnswers] = useState<Record<number, number>>({});
  const [submitted, setSubmitted] = useState<Record<number, boolean>>({});
  const [currentScore, setCurrentScore] = useState(0);

  const handleSelectOption = (questionId: number, optionIndex: number) => {
    if (submitted[questionId]) return;
    setSelectedAnswers((prev) => ({ ...prev, [questionId]: optionIndex }));
  };

  const handleCheckAnswer = (question: QuizQuestion) => {
    if (selectedAnswers[question.id] === undefined) return;
    setSubmitted((prev) => ({ ...prev, [question.id]: true }));
    if (selectedAnswers[question.id] === question.correctIndex) {
      setCurrentScore((prev) => prev + 25);
    }
  };

  const handleResetQuiz = () => {
    setSelectedAnswers({});
    setSubmitted({});
    setCurrentScore(0);
  };

  const completedCount = Object.keys(submitted).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-600/15 text-blue-400 flex items-center justify-center border border-blue-500/30">
              <GraduationCap className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Security Awareness & Scam Defense Academy</h2>
              <p className="text-xs text-slate-400">
                Interactive real-world scenario analysis, red flag dissection, and anti-phishing hygiene training
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Current Score
              </span>
              <p className="text-xl font-bold font-mono text-blue-400 tabular-nums">
                {currentScore} / 100
              </p>
            </div>
            <button
              type="button"
              onClick={handleResetQuiz}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition cursor-pointer"
              title="Reset Quiz"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Progress & Badge */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-5 shadow-sm flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Award className={`w-6 h-6 ${completedCount === QUIZ_QUESTIONS.length && currentScore >= 75 ? 'text-amber-400' : 'text-slate-600'}`} />
          <div>
            <h4 className="text-xs font-semibold text-white">
              {completedCount === QUIZ_QUESTIONS.length
                ? currentScore >= 75
                  ? 'Certified Phishing Defense Specialist'
                  : 'Training Complete — Review Recommended'
                : `Interactive Module Progress (${completedCount}/${QUIZ_QUESTIONS.length} Scenarios)`}
            </h4>
            <p className="text-[11px] text-slate-400">
              Complete each real-world challenge to build threat identification muscle memory.
            </p>
          </div>
        </div>
        <div className="w-32 h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
          <div
            className="h-full bg-blue-500 rounded-full transition-all duration-300"
            style={{ width: `${(completedCount / QUIZ_QUESTIONS.length) * 100}%` }}
          />
        </div>
      </div>

      {/* Question Cards */}
      <div className="space-y-6">
        {QUIZ_QUESTIONS.map((q, index) => {
          const isAnswered = submitted[q.id];
          const selected = selectedAnswers[q.id];
          const isCorrect = selected === q.correctIndex;

          return (
            <div
              key={q.id}
              className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm space-y-4"
            >
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold bg-blue-600/15 text-blue-400 border border-blue-500/30">
                  <BookOpen className="w-3.5 h-3.5" />
                  Scenario #{index + 1}: {q.category}
                </span>
                {isAnswered && (
                  <span
                    className={`inline-flex items-center gap-1 text-xs font-bold ${
                      isCorrect ? 'text-emerald-400' : 'text-red-400'
                    }`}
                  >
                    {isCorrect ? (
                      <>
                        <CheckCircle2 className="w-4 h-4" /> Correct (+25 pts)
                      </>
                    ) : (
                      <>
                        <XCircle className="w-4 h-4" /> Incorrect
                      </>
                    )}
                  </span>
                )}
              </div>

              {/* Scenario Context Box */}
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 leading-relaxed">
                <strong className="text-white block font-sans mb-1 uppercase tracking-wider text-[11px]">
                  Incident Scenario:
                </strong>
                {q.scenario}
              </div>

              <h3 className="text-sm font-semibold text-white">{q.question}</h3>

              {/* Options */}
              <div className="space-y-2">
                {q.options.map((opt, optIdx) => {
                  const isThisSelected = selected === optIdx;
                  let borderClass = 'border-slate-800 hover:border-slate-700 bg-slate-900/40 text-slate-300';

                  if (isAnswered) {
                    if (optIdx === q.correctIndex) {
                      borderClass = 'border-emerald-500/60 bg-emerald-500/10 text-emerald-300 font-medium';
                    } else if (isThisSelected && !isCorrect) {
                      borderClass = 'border-red-500/60 bg-red-500/10 text-red-300';
                    } else {
                      borderClass = 'border-slate-800/60 opacity-40 text-slate-500';
                    }
                  } else if (isThisSelected) {
                    borderClass = 'border-blue-500 bg-blue-600/15 text-white font-medium';
                  }

                  return (
                    <button
                      key={optIdx}
                      type="button"
                      disabled={isAnswered}
                      onClick={() => handleSelectOption(q.id, optIdx)}
                      className={`w-full text-left p-3.5 rounded-lg border text-xs transition flex items-start gap-3 cursor-pointer ${borderClass}`}
                    >
                      <span className="w-5 h-5 rounded-full border border-current flex items-center justify-center shrink-0 text-[11px] font-bold">
                        {String.fromCharCode(65 + optIdx)}
                      </span>
                      <span className="flex-1 leading-relaxed">{opt}</span>
                    </button>
                  );
                })}
              </div>

              {!isAnswered ? (
                <div className="pt-2 flex justify-end">
                  <button
                    type="button"
                    disabled={selected === undefined}
                    onClick={() => handleCheckAnswer(q)}
                    className={`inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold text-white shadow-sm transition cursor-pointer ${
                      selected === undefined
                        ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                        : 'bg-blue-600 hover:bg-blue-500'
                    }`}
                  >
                    Check Answer
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              ) : (
                <div className="pt-3 border-t border-slate-800 space-y-3">
                  <div className="p-4 bg-blue-600/10 border border-blue-500/30 rounded-lg text-xs text-blue-300 space-y-2">
                    <strong className="block font-semibold text-white">SOC Analyst Debriefing:</strong>
                    <p className="leading-relaxed">{q.explanation}</p>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[11px] font-bold uppercase text-slate-400 tracking-wider">
                      Critical Red Flags:
                    </span>
                    <ul className="space-y-1 text-xs text-slate-300">
                      {q.redFlags.map((flag, fIdx) => (
                        <li key={fIdx} className="flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                          <span>{flag}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

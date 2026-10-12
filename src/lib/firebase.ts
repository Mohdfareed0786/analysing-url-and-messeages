import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  User,
} from 'firebase/auth';
import {
  getFirestore,
  doc,
  getDoc,
  getDocFromServer,
  setDoc,
  updateDoc,
  deleteDoc,
  serverTimestamp,
  Timestamp,
} from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();

// Validate connection to Firestore on boot per skill requirements
async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
testConnection();

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

// Validation constants synchronized verbatim with firebase-blueprint.json & firestore.rules
export const VALID_ID_REGEX = /^[a-zA-Z0-9_\-]+$/;
export const MAX_DISPLAY_NAME_LEN = 100;
export const MAX_ORGANIZATION_LEN = 120;
export const MAX_JOB_TITLE_LEN = 100;
export const MAX_EMAIL_LEN = 254;
export const MAX_PHONE_LEN = 32;
export const MAX_TARGET_LEN = 2048;
export const MAX_SUMMARY_LEN = 4000;
export const MAX_REPORT_TITLE_LEN = 200;
export const MAX_ANALYST_NOTES_LEN = 5000;

export function generateSafeId(prefix: string): string {
  const randomPart =
    typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID().replace(/[^a-zA-Z0-9_\-]/g, '')
      : `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const id = `${prefix}_${randomPart}`.slice(0, 120);
  return VALID_ID_REGEX.test(id) ? id : `id_${Date.now()}`;
}

export interface UserProfileDoc {
  uid: string;
  displayName: string;
  organization?: string;
  jobTitle?: string;
  createdAt?: Timestamp;
  updatedAt?: Timestamp;
}

export interface UserPrivateInfoDoc {
  uid: string;
  email?: string;
  phoneNumber?: string;
  authProvider: string;
  updatedAt?: Timestamp;
}

export type AllowedScanType = 'url' | 'message' | 'ip' | 'screenshot';
export type AllowedVerdictType =
  | 'Clean'
  | 'Low Risk'
  | 'Suspicious'
  | 'High Risk'
  | 'Malicious'
  | 'LOW RISK'
  | 'MEDIUM RISK'
  | 'HIGH RISK'
  | 'CRITICAL RISK';

export interface ScanRecordDoc {
  scanId: string;
  userId: string;
  scanType: AllowedScanType;
  target: string;
  riskScore: number;
  verdict: AllowedVerdictType;
  summary: string;
  analysisData: Record<string, unknown>;
  status: 'completed';
  createdAt?: Timestamp;
}

export interface SecurityReportDoc {
  reportId: string;
  userId: string;
  scanId: string;
  title: string;
  scanType: AllowedScanType;
  target: string;
  riskScore: number;
  verdict: AllowedVerdictType;
  analystNotes: string;
  status: 'active' | 'archived';
  createdAt?: Timestamp;
  updatedAt?: Timestamp;
}

export interface ChatTurnItem {
  role: 'user' | 'model';
  text: string;
  timestamp: string;
  sources?: { uri: string; title: string }[];
  executedTools?: {
    toolName: string;
    target: string;
    riskScore: number;
    verdict: string;
    summary: string;
  }[];
}

export interface ChatSessionDoc {
  chatId: string;
  userId: string;
  title: string;
  rolePersona: string;
  modelName: string;
  messages: ChatTurnItem[];
  createdAt?: Timestamp;
  updatedAt?: Timestamp;
}

export async function ensureUserProfile(user: User): Promise<void> {
  const userPath = `users/${user.uid}`;
  const privatePath = `users/${user.uid}/private/info`;

  try {
    const userRef = doc(db, 'users', user.uid);
    const snap = await getDoc(userRef);

    const defaultName = (
      user.displayName ||
      (user.email ? user.email.split('@')[0] : '') ||
      user.phoneNumber ||
      'Security Analyst'
    )
      .trim()
      .slice(0, MAX_DISPLAY_NAME_LEN) || 'Security Analyst';

    if (!snap.exists()) {
      await setDoc(userRef, {
        uid: user.uid,
        displayName: defaultName,
        organization: 'Security Operations Center',
        jobTitle: 'Threat Intelligence Analyst',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }

    const privateRef = doc(db, 'users', user.uid, 'private', 'info');
    const privateSnap = await getDoc(privateRef);
    const providerId = user.providerData?.[0]?.providerId || 'firebase';

    const privatePayload: Record<string, unknown> = {
      uid: user.uid,
      authProvider: providerId.slice(0, 64),
      updatedAt: serverTimestamp(),
    };
    if (user.email) {
      privatePayload.email = user.email.slice(0, MAX_EMAIL_LEN);
    }
    if (user.phoneNumber) {
      privatePayload.phoneNumber = user.phoneNumber.slice(0, MAX_PHONE_LEN);
    }

    if (!privateSnap.exists()) {
      await setDoc(privateRef, privatePayload);
    } else {
      await updateDoc(privateRef, privatePayload);
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `${userPath} | ${privatePath}`);
  }
}

export async function updateAnalystProfile(
  uid: string,
  updates: { displayName: string; organization: string; jobTitle: string }
): Promise<void> {
  const path = `users/${uid}`;
  try {
    const cleanName = updates.displayName.trim().slice(0, MAX_DISPLAY_NAME_LEN) || 'Security Analyst';
    const cleanOrg = updates.organization.trim().slice(0, MAX_ORGANIZATION_LEN);
    const cleanRole = updates.jobTitle.trim().slice(0, MAX_JOB_TITLE_LEN);

    await updateDoc(doc(db, 'users', uid), {
      displayName: cleanName,
      organization: cleanOrg,
      jobTitle: cleanRole,
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function saveScanRecord(params: {
  userId: string;
  scanType: AllowedScanType;
  target: string;
  riskScore: number;
  verdict: AllowedVerdictType;
  summary: string;
  analysisData: Record<string, unknown>;
}): Promise<string> {
  const scanId = generateSafeId('scan');
  const path = `scans/${scanId}`;

  // Sanitize analysisData to remove undefined values for Firestore compatibility
  const sanitizedAnalysis = JSON.parse(JSON.stringify(params.analysisData)) as Record<
    string,
    unknown
  >;

  const boundedScore = Math.max(0, Math.min(100, Math.round(params.riskScore)));
  const cleanTarget = params.target.trim().slice(0, MAX_TARGET_LEN) || 'Unknown Target';
  const cleanSummary =
    params.summary.trim().slice(0, MAX_SUMMARY_LEN) ||
    `Completed ${params.scanType.toUpperCase()} security analysis with score ${boundedScore}/100.`;

  try {
    await setDoc(doc(db, 'scans', scanId), {
      scanId,
      userId: params.userId,
      scanType: params.scanType,
      target: cleanTarget,
      riskScore: boundedScore,
      verdict: params.verdict,
      summary: cleanSummary,
      analysisData: sanitizedAnalysis,
      status: 'completed',
      createdAt: serverTimestamp(),
    });
    return scanId;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function deleteScanRecord(scanId: string): Promise<void> {
  const path = `scans/${scanId}`;
  try {
    await deleteDoc(doc(db, 'scans', scanId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export async function createSecurityReportFromScan(params: {
  userId: string;
  scanId: string;
  title: string;
  scanType: AllowedScanType;
  target: string;
  riskScore: number;
  verdict: AllowedVerdictType;
  analystNotes: string;
}): Promise<string> {
  const reportId = generateSafeId('rep');
  const path = `reports/${reportId}`;

  const cleanTitle =
    params.title.trim().slice(0, MAX_REPORT_TITLE_LEN) ||
    `Security Assessment — ${params.target.slice(0, 60)}`;
  const cleanTarget = params.target.trim().slice(0, MAX_TARGET_LEN) || 'Target';
  const cleanNotes = params.analystNotes.trim().slice(0, MAX_ANALYST_NOTES_LEN);
  const boundedScore = Math.max(0, Math.min(100, Math.round(params.riskScore)));

  try {
    await setDoc(doc(db, 'reports', reportId), {
      reportId,
      userId: params.userId,
      scanId: params.scanId,
      title: cleanTitle,
      scanType: params.scanType,
      target: cleanTarget,
      riskScore: boundedScore,
      verdict: params.verdict,
      analystNotes: cleanNotes,
      status: 'active',
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return reportId;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function updateSecurityReportNotes(
  reportId: string,
  title: string,
  analystNotes: string
): Promise<void> {
  const path = `reports/${reportId}`;
  try {
    await updateDoc(doc(db, 'reports', reportId), {
      title: title.trim().slice(0, MAX_REPORT_TITLE_LEN) || 'Security Assessment Report',
      analystNotes: analystNotes.trim().slice(0, MAX_ANALYST_NOTES_LEN),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function archiveSecurityReport(reportId: string): Promise<void> {
  const path = `reports/${reportId}`;
  try {
    await updateDoc(doc(db, 'reports', reportId), {
      status: 'archived',
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function deleteSecurityReport(reportId: string): Promise<void> {
  const path = `reports/${reportId}`;
  try {
    await deleteDoc(doc(db, 'reports', reportId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export async function saveChatSession(params: {
  chatId?: string;
  userId: string;
  title: string;
  rolePersona: string;
  modelName: string;
  messages: ChatTurnItem[];
}): Promise<string> {
  const isNew = !params.chatId;
  const chatId = params.chatId && VALID_ID_REGEX.test(params.chatId)
    ? params.chatId
    : generateSafeId('chat');
  const path = `chats/${chatId}`;

  const cleanTitle = params.title.trim().slice(0, 200) || 'SOC AI Investigation';
  const cleanRole = params.rolePersona.trim().slice(0, 100) || 'soc-analyst';
  const cleanModel = params.modelName.trim().slice(0, 100) || 'gemini-3.8-flash';
  const boundedMessages = JSON.parse(
    JSON.stringify(params.messages.slice(-50))
  ) as ChatTurnItem[];

  try {
    if (isNew) {
      await setDoc(doc(db, 'chats', chatId), {
        chatId,
        userId: params.userId,
        title: cleanTitle,
        rolePersona: cleanRole,
        modelName: cleanModel,
        messages: boundedMessages,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(doc(db, 'chats', chatId), {
        title: cleanTitle,
        rolePersona: cleanRole,
        modelName: cleanModel,
        messages: boundedMessages,
        updatedAt: serverTimestamp(),
      });
    }
    return chatId;
  } catch (error) {
    handleFirestoreError(error, isNew ? OperationType.CREATE : OperationType.UPDATE, path);
  }
}

export async function deleteChatSession(chatId: string): Promise<void> {
  const path = `chats/${chatId}`;
  try {
    await deleteDoc(doc(db, 'chats', chatId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}


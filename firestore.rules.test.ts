/**
 * Phase 0 & Phase 5 Security Rules Verification Spec
 * Verifies that all "Dirty Dozen" adversarial payloads are rejected with PERMISSION_DENIED.
 */

export interface AdversarialTestCase {
  id: number;
  name: string;
  collectionPath: string;
  operation: 'get' | 'list' | 'create' | 'update' | 'delete';
  authUid: string | null;
  payload?: Record<string, unknown>;
  expectedOutcome: 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_TEST_CASES: AdversarialTestCase[] = [
  {
    id: 1,
    name: 'Shadow Field Injection on UserProfile',
    collectionPath: '/users/user_1',
    operation: 'create',
    authUid: 'user_1',
    payload: {
      uid: 'user_1',
      displayName: 'Alice',
      isAdmin: true,
    },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 2,
    name: 'Identity Spoofing on ScanRecord',
    collectionPath: '/scans/scan_1',
    operation: 'create',
    authUid: 'user_1',
    payload: {
      scanId: 'scan_1',
      userId: 'user_2',
      scanType: 'url',
      target: 'https://example.com',
      riskScore: 10,
      verdict: 'Clean',
      summary: 'Test',
      analysisData: {},
      status: 'completed',
    },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 3,
    name: 'Cross-Tenant PII Read',
    collectionPath: '/users/user_1/private/info',
    operation: 'get',
    authUid: 'user_2',
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 4,
    name: 'Unconstrained List Scraping on Scans',
    collectionPath: '/scans',
    operation: 'list',
    authUid: 'user_2',
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 5,
    name: 'ID Poisoning with Special Characters',
    collectionPath: '/scans/invalid$id!@#',
    operation: 'create',
    authUid: 'user_1',
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 6,
    name: 'Value Poisoning on Risk Score (>100)',
    collectionPath: '/scans/scan_1',
    operation: 'create',
    authUid: 'user_1',
    payload: {
      scanId: 'scan_1',
      userId: 'user_1',
      scanType: 'url',
      target: 'https://example.com',
      riskScore: 999,
      verdict: 'Clean',
      summary: 'Test',
      analysisData: {},
      status: 'completed',
    },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 7,
    name: 'Audit Tampering / Updating Completed Scan',
    collectionPath: '/scans/scan_1',
    operation: 'update',
    authUid: 'user_1',
    payload: { riskScore: 0 },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 8,
    name: 'Orphaned Security Report Without Existing Scan',
    collectionPath: '/reports/rep_1',
    operation: 'create',
    authUid: 'user_1',
    payload: {
      reportId: 'rep_1',
      userId: 'user_1',
      scanId: 'non_existent_scan',
      title: 'Report',
      scanType: 'url',
      target: 'https://example.com',
      riskScore: 50,
      verdict: 'Suspicious',
      analystNotes: 'Notes',
      status: 'active',
    },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 9,
    name: 'Cross-User Scan Reference in Report',
    collectionPath: '/reports/rep_1',
    operation: 'create',
    authUid: 'user_1',
    payload: {
      reportId: 'rep_1',
      userId: 'user_1',
      scanId: 'user_2_scan_id',
      title: 'Report',
      scanType: 'url',
      target: 'https://example.com',
      riskScore: 50,
      verdict: 'Suspicious',
      analystNotes: 'Notes',
      status: 'active',
    },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 10,
    name: 'Terminal State Bypass on Archived Report',
    collectionPath: '/reports/rep_archived',
    operation: 'update',
    authUid: 'user_1',
    payload: { analystNotes: 'Modified after archive' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 11,
    name: 'Forged Client Timestamp on Create',
    collectionPath: '/scans/scan_1',
    operation: 'create',
    authUid: 'user_1',
    payload: { createdAt: '2020-01-01T00:00:00Z' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 12,
    name: 'Oversized String Denial-of-Wallet',
    collectionPath: '/reports/rep_1',
    operation: 'update',
    authUid: 'user_1',
    payload: { analystNotes: 'A'.repeat(10000) },
    expectedOutcome: 'PERMISSION_DENIED',
  },
];

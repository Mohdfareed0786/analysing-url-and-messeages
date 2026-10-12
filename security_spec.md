# Phishing Shield — Firestore Security Specification (Phase 0 TDD)

## 1. Data Invariants

1. **Default-Deny Catch-All**: All unmatched paths (`/{document=**}`) deny all reads and writes unconditionally.
2. **PII Split Collection Isolation**: User PII (`email`, `phoneNumber`) is stored strictly inside `/users/{userId}/private/{docId}` and never inside `/users/{userId}`. Only the owner (`request.auth.uid == userId`) can read or write either document, and `/users/{userId}/private/{docId}` requires the parent `/users/{userId}` document to exist (`exists()`).
3. **Strict Ownership Isolation**: Users can only read, list, create, update, or delete their own `/scans/{scanId}` and `/reports/{reportId}` documents (`resource.data.userId == request.auth.uid` on reads/lists, `request.resource.data.userId == request.auth.uid` on writes).
4. **Relational Consistency**: Creating a `/reports/{reportId}` document requires that the referenced `/scans/{scanId}` document exists and is owned by `request.auth.uid`.
5. **Terminal State & Immutability**:
   - `/scans/{scanId}` documents are created in terminal status `'completed'` and cannot be updated (`allow update: if false;`), preserving audit log integrity.
   - `/reports/{reportId}` documents lock updates once `existing().status == 'archived'`.
6. **Strict Timestamp Enforcement**: All `createdAt` and `updatedAt` fields must equal `request.time`.

## 2. The "Dirty Dozen" Adversarial Payloads

1. **Payload 1 (Shadow Field Injection on UserProfile)**: `{ uid: "user_1", displayName: "Alice", createdAt: SERVER_TIME, updatedAt: SERVER_TIME, isAdmin: true }` -> Rejected by `hasOnly`.
2. **Payload 2 (Identity Spoofing on ScanRecord)**: Authenticated as `user_1`, creating `/scans/scan_1` with `{ userId: "user_2", ... }` -> Rejected by `data.userId == request.auth.uid`.
3. **Payload 3 (Cross-Tenant PII Read)**: Authenticated as `user_2`, reading `/users/user_1/private/info` -> Rejected by `request.auth.uid == userId`.
4. **Payload 4 (Unconstrained List Scraping on Scans)**: Authenticated as `user_1`, running `getDocs(collection(db, 'scans'))` without `where('userId', '==', 'user_1')` -> Rejected by `allow list: if isSignedIn() && resource.data.userId == request.auth.uid`.
5. **Payload 5 (ID Poisoning / 2KB Document ID)**: Creating `/scans/<200-char-id>` -> Rejected by `isValidId(scanId)`.
6. **Payload 6 (Value Poisoning on Risk Score)**: Creating `/scans/scan_1` with `riskScore: 999` or `riskScore: "high"` -> Rejected by `data.riskScore is int && data.riskScore >= 0 && data.riskScore <= 100`.
7. **Payload 7 (Audit Tampering / Updating Completed Scan)**: Attempting `updateDoc` on `/scans/scan_1` -> Rejected because `allow update: if false`.
8. **Payload 8 (Orphaned Security Report)**: Creating `/reports/rep_1` referencing a non-existent `scanId: "ghost_scan"` -> Rejected by `exists(/databases/$(database)/documents/scans/$(incoming().scanId))`.
9. **Payload 9 (Cross-User Scan Reference in Report)**: Creating `/reports/rep_1` referencing `scanId` owned by `user_2` -> Rejected by `get(/databases/$(database)/documents/scans/$(incoming().scanId)).data.userId == request.auth.uid`.
10. **Payload 10 (Terminal State Bypass on Archived Report)**: Updating `analystNotes` on a report where `existing().status == 'archived'` -> Rejected by `existing().status != 'archived'`.
11. **Payload 11 (Forged Client Timestamp)**: Creating `/scans/scan_1` with a past/future `createdAt` timestamp instead of `serverTimestamp()` -> Rejected by `data.createdAt == request.time`.
12. **Payload 12 (Oversized String Denial-of-Wallet)**: Updating `analystNotes` on `/reports/rep_1` with a 50,000-character string -> Rejected by `data.analystNotes.size() <= 5000`.

// Reference data transcribed from the iAM Smart API Specification v2.5.2.

/** §2.4.3 Return codes. */
export const returnCodes = [
  { group: 'Success', codes: [['D00000', 'SUCCESS']] },
  {
    group: 'Common',
    codes: [
      ['D20000', 'unknown exception'],
      ['D20001', 'parameter {%s} is missing'],
      ['D20002', 'empty parameter {%s}'],
      ['D20003', 'invalid parameter {%s}'],
      ['D20004', 'duplicated request'],
      ['D20005', 'unsupported signature method'],
      ['D20006', 'signature verification failed'],
      ['D20007', 'unsupported source'],
      ['D20008', 'invalid online service URL — the callback URL is not registered in the ESP portal'],
      ['D20009', 'accessToken not exist or expired'],
      ['D20010', 'openID not exist'],
      ['D20011', 'duplicated businessID'],
      ['D20012', 'insufficient permission for online service / Forbidden — check the scope or API access control in the ESP portal'],
      ['D20015', 'scope mismatch — verify the scopes approved for the client ID in the ESP and the scopes configured in the online service catalogue'],
    ],
  },
  {
    group: 'Encryption / decryption',
    codes: [
      ['D30001', 'key encryption key not exist or expired'],
      ['D30002', 'content encryption key not exist or expired'],
      ['D30003', 'encryption exception'],
      ['D30004', 'decryption exception'],
    ],
  },
  {
    group: 'Authentication',
    codes: [
      ['D40000', 'user cancelled authentication request'],
      ['D40001', 'user rejected authentication request'],
      ['D40002', 'failed to authenticate'],
      ['D40003', 'authentication request timeout'],
      ['D40004', 'authCode not exist or expired'],
    ],
  },
  {
    group: 'Profile request',
    codes: [
      ['D50001', 'user rejected profile request'],
      ['D50002', 'failed to request profile'],
      ['D50003', 'profile request timeout'],
    ],
  },
  {
    group: 'Form filling',
    codes: [
      ['D60000', 'user cancelled Form Filling request'],
      ['D60001', 'user rejected Form Filling request'],
      ['D60002', 'failed to request Form Filling'],
      ['D60003', 'Form Filling request timeout'],
    ],
  },
  {
    group: 'Signing',
    codes: [
      ['D70000', 'user cancelled signing request'],
      ['D70001', 'user rejected signing request'],
      ['D70002', 'failed to request signing'],
      ['D70003', 'signing request timeout'],
      ['D70004', 'user not allowed to sign'],
      ['D70005', 'inconsistent HKIC number'],
      ['D70006', 'failed to process signing acknowledgement'],
      ['D77003', 'device not supported for NFC'],
      ['D77004', 'user is still in waiting period'],
    ],
  },
  {
    group: 'Bulk digital signing',
    codes: [
      ['D71000', 'user cancelled bulk signing request'],
      ['D71001', 'user rejected bulk signing request'],
      ['D71002', 'failed to request signing'],
      ['D71003', 'signing request timeout'],
      ['D71004', 'user is not allowed to sign'],
      ['D71005', 'inconsistent HKIC number'],
      ['D71006', 'failed to process signing acknowledgement'],
      ['D71007', 'the request to be cancelled is not Pending for Signing'],
      ['D71008', 'BSQC Token not found'],
      ['D71009', 'inconsistent department or service name'],
    ],
  },
  {
    group: 'Re-authentication',
    codes: [
      ['D80001', 'user rejected re-authentication request'],
      ['D80002', 'failed to request re-authentication'],
      ['D80003', 're-authentication request timeout'],
    ],
  },
  {
    group: 'Step-up authentication',
    codes: [
      ['D41001', 'user rejected step-up authentication request'],
      ['D41002', 'step-up authentication request timeout'],
      ['D41003', 'inconsistent HKIC number'],
      ['D41500', 'failed to step-up authenticate'],
      ['D41503', 'device not supported for NFC'],
      ['D41006', 'user is still in waiting period'],
      ['D41007', 'user is not allowed to step-up authentication'],
    ],
  },
  {
    group: 'CDEG consent',
    codes: [
      ['D42001', 'user rejected CDEG consent request'],
      ['D42002', 'CDEG consent request timeout'],
      ['D42003', 'failed to CDEG consent request'],
    ],
  },
]

/** Hints added by this site (not part of the spec). */
export const returnCodeHints = {
  D20001: 'A required field or header is missing; the message names it.',
  D20004: 'The request looks like a replay. Use a fresh nonce and a non-decreasing timestamp for every call.',
  D20006: 'Sign exactly the body bytes you send, after encryption, and URL-encode the Base64 signature.',
  D20008: 'Register the exact redirect/callback URL in the Self-Service Portal.',
  D20012: 'The scope or API is not approved for this client ID.',
  D30001: 'Upload or renew the KEK certificate in the Self-Service Portal.',
  D30002: 'Call Request CEK again and retry with the new key.',
  D30004: 'Check AES-256-GCM, the 12-byte IV and the int32 IV-length prefix.',
  D40004: 'Auth codes are single use and expire in 30–60 seconds.',
}

/** Appendix B — values for the `source` parameter. */
export const sources = [
  { platform: 'Android browser', client: 'Chrome', value: 'Android_Chrome' },
  { platform: 'Android browser', client: 'Firefox', value: 'Android_Firefox' },
  { platform: 'Android browser', client: 'Edge', value: 'Android_Edge' },
  { platform: 'Android browser', client: 'Samsung built-in browser', value: 'Android_Samsung' },
  { platform: 'Android browser', client: 'Huawei built-in browser', value: 'Android_Huawei' },
  { platform: 'Android browser', client: 'Xiaomi built-in browser', value: 'Android_Xiaomi' },
  { platform: 'Android browser', client: 'In-app browser (iAM Smart)', value: 'Android_IMS_InAppBrowser' },
  { platform: 'iOS browser', client: 'Safari', value: 'iOS_Safari' },
  { platform: 'iOS browser', client: 'Chrome', value: 'iOS_Chrome' },
  { platform: 'iOS browser', client: 'Firefox', value: 'iOS_Firefox' },
  { platform: 'iOS browser', client: 'Edge', value: 'iOS_Edge' },
  { platform: 'iOS browser', client: 'In-app browser (iAM Smart)', value: 'iOS_IMS_InAppBrowser' },
  { platform: 'Desktop browser', client: 'Chrome, IE, Edge, Firefox, Safari', value: 'PC_Browser' },
  { platform: 'Online service app (appv2)', client: 'Invoked by Universal Link (iOS)', value: 'App_Link' },
  { platform: 'Online service app (appv2)', client: 'Invoked by package name (Android)', value: 'App_Package' },
  { platform: 'Online service app (appv1)', client: 'Invoked by URL scheme', value: 'App_Scheme' },
  { platform: 'Online service app (appv1)', client: 'Invoked by Universal Link (iOS) / App Link (Android)', value: 'App_Link' },
]

export const scopes = [
  { value: 'eidapi_auth', api: 'Authentication (also CDEG Integration)' },
  { value: 'eidapi_profiles', api: 'Form Filling with Service Login (Profiles API)' },
  { value: 'eidapi_formFilling', api: 'Form Filling (v2) and Anonymous Form Filling' },
  { value: 'eidapi_sign', api: 'Digital Signing, with or without service login' },
  { value: 'eidapi_fr', api: 'Re-authentication with service login' },
  { value: 'eidapi_bulksign', api: 'Bulk Digital Signing, with or without service login' },
  { value: 'eidapi_sua', api: 'Step-up Authentication, with or without service login' },
]

export const environments = {
  testing: {
    label: 'Testing',
    domain: 'apigw-isit.staging-eid.gov.hk',
    scheme: 'hk.gov.iamsmart.testapp',
    portal: 'https://portal-isit.staging-eid.gov.hk/ESP/index.html',
  },
  production: {
    label: 'Production',
    domain: 'apigw.iamsmart.gov.hk',
    scheme: 'hk.gov.iamsmart',
    portal: 'https://portal.iamsmart.gov.hk/ESP/index.html',
  },
}

/** Deep links into the iAM Smart app (`<scheme>://<action>`). */
export const deepLinks = [
  { action: 'auth', feature: 'Authentication', version: 'appv1', section: '3.4.2', params: ['clientID', 'responseType', 'source', 'redirectURI', 'scope', 'state'] },
  { action: 'v2_auth', feature: 'Authentication', version: 'appv2', section: '3.4.8', params: ['clientID', 'responseType', 'source', 'clientRedirectURI', 'packageName', 'activityClass', 'activityParams', 'scope', 'state'] },
  { action: 'form-filling', feature: 'Form Filling', version: 'appv1', section: '4.2.5.2', params: ['ticketID'] },
  { action: 'v2_form-filling', feature: 'Form Filling', version: 'appv2', section: '4.2.5.2', params: ['ticketID'] },
  { action: 'anon_form-filling', feature: 'Anonymous Form Filling', version: 'appv1', section: '5.5.3', params: ['ticketID', 'source', 'redirectURI', 'state'] },
  { action: 'v2_anon_form-filling', feature: 'Anonymous Form Filling', version: 'appv2', section: '5.5.8', params: ['ticketID', 'source', 'clientRedirectURI', 'packageName', 'activityClass', 'activityParams', 'state'] },
  { action: 'hash-sign', feature: 'Digital Signing (hash)', version: 'appv1', section: '6.5.3', params: ['ticketID'] },
  { action: 'pdf-sign', feature: 'Digital Signing (PDF)', version: 'appv1', section: '6.5.3', params: ['ticketID'] },
  { action: 'v2_hash-sign', feature: 'Digital Signing (hash)', version: 'appv2', section: '6.5.3', params: ['ticketID'] },
  { action: 'v2_pdf-sign', feature: 'Digital Signing (PDF)', version: 'appv2', section: '6.5.3', params: ['ticketID'] },
  { action: 'anon_hash-sign', feature: 'Anonymous Digital Signing (hash)', version: 'appv1', section: '7.5.4', params: ['ticketID', 'source', 'redirectURI', 'state'] },
  { action: 'anon_pdf-sign', feature: 'Anonymous Digital Signing (PDF)', version: 'appv1', section: '7.5.4', params: ['ticketID', 'source', 'redirectURI', 'state'] },
  { action: 'v2_anon_hash-sign', feature: 'Anonymous Digital Signing (hash)', version: 'appv2', section: '7.5.11', params: ['ticketID', 'source', 'clientRedirectURI', 'packageName', 'activityClass', 'activityParams', 'state'] },
  { action: 'v2_anon_pdf-sign', feature: 'Anonymous Digital Signing (PDF)', version: 'appv2', section: '7.5.11', params: ['ticketID', 'source', 'clientRedirectURI', 'packageName', 'activityClass', 'activityParams', 'state'] },
  { action: 're-auth', feature: 'Re-authentication', version: 'appv1', section: '8.5.2', params: ['ticketID'] },
  { action: 'v2_re-auth', feature: 'Re-authentication', version: 'appv2', section: '8.5.2', params: ['ticketID'] },
  { action: 'bulk-sign', feature: 'Bulk Digital Signing', version: 'appv1', section: '9.5.2', params: ['ticketID'] },
  { action: 'v2_bulk-sign', feature: 'Bulk Digital Signing', version: 'appv2', section: '9.5.2', params: ['ticketID'] },
  { action: 'anon_bulk-sign', feature: 'Anonymous Bulk Digital Signing', version: 'appv1', section: '10.5.3', params: ['ticketID', 'source', 'redirectURI', 'state'] },
  { action: 'v2_anon_bulk-sign', feature: 'Anonymous Bulk Digital Signing', version: 'appv2', section: '10.5.11', params: ['ticketID', 'source', 'clientRedirectURI', 'packageName', 'activityClass', 'activityParams', 'state'] },
  { action: 'sua', feature: 'Step-up Authentication', version: 'appv1', section: '11.5.2', params: ['ticketID'] },
  { action: 'v2_sua', feature: 'Step-up Authentication', version: 'appv2', section: '11.5.2', params: ['ticketID'] },
  { action: 'anon_sua', feature: 'Anonymous Step-up Authentication', version: 'appv1', section: '12.5.3', params: ['ticketID', 'source', 'redirectURI', 'state'] },
  { action: 'v2_anon_sua', feature: 'Anonymous Step-up Authentication', version: 'appv2', section: '12.5.8', params: ['ticketID', 'source', 'clientRedirectURI', 'packageName', 'activityClass', 'activityParams', 'state'] },
  { action: 'request-consent', feature: 'CDEG consent', version: 'v1', section: '13.5.3', params: ['ticketID'] },
]

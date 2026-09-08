export type S2SAuthErrorCode = 'UNTRUSTED_ISSUER' | 'INVALID_TOKEN';

export class S2SAuthError extends Error {
     constructor(
          public readonly code: S2SAuthErrorCode,
          message: string,
     ) {
          super(message);
          this.name = 'S2SAuthError';
     }
}

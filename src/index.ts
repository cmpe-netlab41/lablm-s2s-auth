export { S2SAuthError, type S2SAuthErrorCode } from './errors';
export { LazyEdDSAPublicKey, LazyEdDSAPrivateKey } from './jwt/keys';
export { signEdDSAJwt, verifyEdDSAJwt, type SignEdDSAJwtOptions, type VerifyEdDSAJwtOptions } from './jwt/low-level';
export {
     S2SBaseClaimsSchema,
     type S2SBaseClaims,
     type TrustedIssuer,
     IssuerKeyRegistry,
     signS2SToken,
     verifyS2SToken,
     type SignS2STokenOptions,
     type VerifyS2STokenOptions,
} from './jwt/s2s-token';
export { ReplayProtectionStore } from './replay/replay-protection.store';
export { createS2STokenMinter, type CreateS2STokenMinterOptions } from './client/create-s2s-token-minter';
export {
     createS2SAuthStrategy,
     type CreateS2SAuthStrategyOptions,
     type S2SCallContext,
} from './client/create-s2s-auth-strategy';

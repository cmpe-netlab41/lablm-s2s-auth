import { SetMetadata } from '@nestjs/common';

export const S2S_AUTH_EXEMPT_KEY = 's2s-auth:exempt';

/**
 * Marks a route as exempt from the generic `S2SAuthGuard` global guard.
 * `reason` is never read at runtime — it exists purely so an exemption is
 * self-documenting at the call site and easy to challenge in review.
 */
export const S2SAuthExempt = (reason: string) => SetMetadata(S2S_AUTH_EXEMPT_KEY, reason);

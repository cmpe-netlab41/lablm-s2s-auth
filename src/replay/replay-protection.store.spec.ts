import { ReplayProtectionStore } from './replay-protection.store';

describe('ReplayProtectionStore', () => {
     it('consumes a jti the first time and rejects the second attempt', () => {
          const store = new ReplayProtectionStore();
          const now = 1_000;

          expect(store.consume('jti-1', now + 60, now)).toBe(true);
          expect(store.consume('jti-1', now + 60, now)).toBe(false);
     });

     it('tracks distinct jtis independently', () => {
          const store = new ReplayProtectionStore();
          const now = 1_000;

          expect(store.consume('jti-1', now + 60, now)).toBe(true);
          expect(store.consume('jti-2', now + 60, now)).toBe(true);
     });

     it('sweeps expired entries so a jti can theoretically be reused only after its own token could no longer verify', () => {
          const store = new ReplayProtectionStore();
          const mintedAt = 1_000;
          const expiresAt = mintedAt + 60;

          expect(store.consume('jti-1', expiresAt, mintedAt)).toBe(true);

          // Sweeping happens on the next consume() call, keyed off "now" — an
          // expired entry no longer blocks reuse of the same jti.
          expect(store.consume('jti-1', expiresAt, expiresAt + 1)).toBe(true);
     });
});

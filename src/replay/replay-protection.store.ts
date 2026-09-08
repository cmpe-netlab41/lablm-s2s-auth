/**
 * Single-process, atomic one-time token consumption.
 *
 * A synchronous Map gives SETNX semantics as long as the consuming process
 * is the sole authority for its trust boundary (e.g. one agent process per
 * machine). Entries expire with their JWTs.
 */
export class ReplayProtectionStore {
     private readonly consumedTokenExpirations = new Map<string, number>();

     consume(jti: string, expiresAtEpochSeconds: number, nowEpochSeconds = Math.floor(Date.now() / 1000)): boolean {
          this.removeExpired(nowEpochSeconds);

          if (this.consumedTokenExpirations.has(jti)) return false;

          this.consumedTokenExpirations.set(jti, expiresAtEpochSeconds);
          return true;
     }

     private removeExpired(nowEpochSeconds: number): void {
          for (const [jti, expiresAt] of this.consumedTokenExpirations) {
               if (expiresAt <= nowEpochSeconds) this.consumedTokenExpirations.delete(jti);
          }
     }
}

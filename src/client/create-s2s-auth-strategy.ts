import { createS2STokenMinter, type CreateS2STokenMinterOptions } from './create-s2s-token-minter';

export interface S2SCallContext {
     targetService: string;
}

export interface CreateS2SAuthStrategyOptions extends CreateS2STokenMinterOptions {
     claims?: (ctx: S2SCallContext) => Record<string, unknown> | undefined;
}

/**
 * Produces a function shaped like `@lablm/transport`'s `AuthStrategy`
 * (`(ctx) => Promise<Record<string,string>>`) without depending on that
 * package — the parameter is typed to only what's used, so it's assignable
 * to `AuthStrategy` by structural typing.
 */
export function createS2SAuthStrategy(
     opts: CreateS2SAuthStrategyOptions,
): (ctx: S2SCallContext) => Promise<Record<string, string>> {
     const mint = createS2STokenMinter(opts);

     return async (ctx: S2SCallContext) => {
          const token = await mint(ctx.targetService, opts.claims?.(ctx));
          return { Authorization: `Bearer ${token}` };
     };
}

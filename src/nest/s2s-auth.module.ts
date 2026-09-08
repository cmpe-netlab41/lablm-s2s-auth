import { DynamicModule, InjectionToken, Module, Type } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { IssuerKeyRegistry, TrustedIssuer } from '../jwt/s2s-token';
import { S2SAuthGuard, S2S_AUTH_MODULE_OPTIONS } from './s2s-auth.guard';
import { S2SReplayProtectionService } from './s2s-replay-protection.service';

export interface S2SAuthModuleOptions {
     audience: string;
     trustedIssuers: TrustedIssuer[];
}

export interface S2SAuthModuleAsyncOptions {
     imports?: (Type | DynamicModule)[];
     inject?: InjectionToken[];
     useFactory: (...args: unknown[]) => S2SAuthModuleOptions | Promise<S2SAuthModuleOptions>;
}

/**
 * Registers `S2SAuthGuard` as the application's `APP_GUARD` from inside this
 * module, so importing `S2SAuthModule.forRootAsync(...)` once is sufficient
 * for fail-closed protection — a consuming app cannot forget to wire the
 * guard up separately.
 */
@Module({})
export class S2SAuthModule {
     static forRootAsync(opts: S2SAuthModuleAsyncOptions): DynamicModule {
          return {
               module: S2SAuthModule,
               global: true,
               imports: opts.imports ?? [],
               providers: [
                    {
                         provide: S2S_AUTH_MODULE_OPTIONS,
                         inject: opts.inject ?? [],
                         useFactory: async (...args: unknown[]) => {
                              const resolved = await opts.useFactory(...args);
                              return {
                                   audience: resolved.audience,
                                   registry: new IssuerKeyRegistry(resolved.trustedIssuers),
                              };
                         },
                    },
                    S2SReplayProtectionService,
                    S2SAuthGuard,
                    { provide: APP_GUARD, useExisting: S2SAuthGuard },
               ],
               exports: [S2SAuthGuard, S2SReplayProtectionService],
          };
     }
}

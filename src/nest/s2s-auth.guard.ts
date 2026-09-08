import { CanActivate, ExecutionContext, HttpException, HttpStatus, Inject, Injectable, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IssuerKeyRegistry, S2SBaseClaims, verifyS2SToken } from '../jwt/s2s-token';
import { S2S_AUTH_EXEMPT_KEY } from './s2s-auth-exempt.decorator';
import { S2SReplayProtectionService } from './s2s-replay-protection.service';

export const S2S_AUTH_MODULE_OPTIONS = Symbol('S2S_AUTH_MODULE_OPTIONS');

export interface ResolvedS2SAuthOptions {
     audience: string;
     registry: IssuerKeyRegistry;
}

@Injectable()
export class S2SAuthGuard implements CanActivate {
     private readonly logger = new Logger(S2SAuthGuard.name);

     constructor(
          private readonly reflector: Reflector,
          @Inject(S2S_AUTH_MODULE_OPTIONS) private readonly options: ResolvedS2SAuthOptions,
          private readonly replayProtection: S2SReplayProtectionService,
     ) {}

     async canActivate(context: ExecutionContext): Promise<boolean> {
          const exemptReason = this.reflector.getAllAndOverride<string | undefined>(S2S_AUTH_EXEMPT_KEY, [
               context.getHandler(),
               context.getClass(),
          ]);
          if (exemptReason !== undefined) return true;

          const request = context.switchToHttp().getRequest();

          const token = this.extractBearerToken(request);
          if (!token) throw new HttpException('S2S_TOKEN_MISSING', HttpStatus.UNAUTHORIZED);

          let claims: S2SBaseClaims;
          try {
               claims = await verifyS2SToken({ token, audience: this.options.audience, registry: this.options.registry });
          } catch (error) {
               // Log the reason server-side; never leak which check failed (bad
               // signature, untrusted issuer, wrong audience, malformed claims)
               // to the client — same style as FmsOperationGuard/InferenceOperationGuard.
               this.logger.warn(`S2S token rejected: ${error instanceof Error ? error.name : 'unknown'}`);
               throw new HttpException('S2S_TOKEN_INVALID', HttpStatus.UNAUTHORIZED);
          }

          if (!this.replayProtection.consume(claims.jti, claims.exp)) {
               throw new HttpException('S2S_TOKEN_REPLAYED', HttpStatus.UNAUTHORIZED);
          }

          request.s2sToken = claims;
          return true;
     }

     private extractBearerToken(request: { headers: Record<string, unknown> }): string | null {
          const raw = request.headers['authorization'];
          if (typeof raw !== 'string') return null;

          const [scheme, value] = raw.split(' ');
          return scheme === 'Bearer' && value ? value : null;
     }
}

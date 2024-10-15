import { Reflector } from '@nestjs/core';
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';

import { AllowedLimits, OptionalAuthorization } from '../decorators';
import { TokenService } from '../../modules/tokens';
import { CookieService } from '../../modules/cookies';
import { extractToken } from '../helpers';
import { ApiError } from '../errors';
import { Errors } from '../constants';
import { TokenStatuses } from '../enums';

@Injectable()
export class AuthorizedGuard implements CanActivate {
  constructor(
    private readonly tokensService: TokenService,
    private readonly cookiesService: CookieService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const httpContext = context.switchToHttp();
    const contextHandler = context.getHandler();

    const request = httpContext.getRequest<FastifyRequest>();
    const response = httpContext.getResponse<FastifyReply>();

    const isOptional = this.reflector.get(
      OptionalAuthorization,
      contextHandler,
    );

    let isApiToken = false;
    let token: string | null = null;

    const accessTokenCookie = this.cookiesService.get(request, 'accessToken');
    const authorizationHeader = request.headers['authorization'];

    if (accessTokenCookie) {
      token = accessTokenCookie;
    } else {
      token = extractToken(authorizationHeader);
      isApiToken = true;
    }

    if (!token) {
      if (isOptional) {
        (request as any).auth = null;
        return true;
      }

      if (!isApiToken) {
        this.cookiesService.delete(response, 'accessToken', { path: '/' });
      }

      throw new ApiError(Errors.JWT_TOKEN_INVALID);
    }

    const tokenInfo = await this.tokensService.validateToken(token, isApiToken);
    if (!tokenInfo) {
      if (!isApiToken) {
        this.cookiesService.delete(response, 'accessToken', { path: '/' });
      }
      throw new ApiError(Errors.JWT_TOKEN_INVALID);
    }

    if (tokenInfo.status !== TokenStatuses.ACTIVE) {
      throw new ApiError(Errors.JWT_TOKEN_INACTIVE);
    }

    (request as any).auth = tokenInfo.decoded;

    const tokenLimits = tokenInfo.decoded.limits;
    const allowedLimits = this.reflector.get(AllowedLimits, contextHandler);

    if (
      !allowedLimits ||
      (Array.isArray(allowedLimits)
        ? allowedLimits.includes(tokenLimits)
        : allowedLimits === tokenLimits)
    ) {
      return true;
    }

    throw new ApiError(Errors.FORBIDDEN_WITH_TOKEN_LIMITS);
  }
}

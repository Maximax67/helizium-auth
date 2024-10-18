import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { TokenTypes } from '../enums';
import { AuthorizedRequest } from '../interfaces';
import { OptionalAuthorization } from '../decorators';
import { ApiError } from '../errors';
import { Errors } from '../constants';

@Injectable()
export class ForbidApiTokensGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const isOptional = this.reflector.get(
      OptionalAuthorization,
      context.getHandler(),
    );

    if (isOptional) {
      return true;
    }

    const request = context.switchToHttp().getRequest<AuthorizedRequest>();
    const tokenType = request.auth.type;

    if (tokenType === TokenTypes.API) {
      throw new ApiError(Errors.FORBIDDEN_WITH_API_TOKENS);
    }

    return true;
  }
}

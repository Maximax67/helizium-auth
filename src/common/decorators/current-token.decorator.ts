import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { AuthorizedRequest } from '../interfaces';

export const CurrentToken = createParamDecorator(
  (_data: never, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest<AuthorizedRequest>();
    return request.auth;
  },
);

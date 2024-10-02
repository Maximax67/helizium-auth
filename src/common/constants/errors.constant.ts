import { HttpStatus } from '@nestjs/common';
import { ApiErrorTemplate } from '../interfaces';

const errorTemplates = {
  JWT_TOKEN_INVALID_OR_MISSING: {
    message: 'JWT token is invalid or missing',
    status: HttpStatus.UNAUTHORIZED,
  },
  FORBIDDEN_WITH_TOKEN_LIMITS: {
    message: 'Forbidden access with current token limits',
    status: HttpStatus.FORBIDDEN,
  },
} as const;

type ErrorCodes = keyof typeof errorTemplates;

const createErrorTemplate = <T extends ErrorCodes>(
  key: T,
  template: Omit<ApiErrorTemplate, 'id'>,
): ApiErrorTemplate => ({
  id: key,
  ...template,
});

const templates: Record<ErrorCodes, ApiErrorTemplate> = Object.fromEntries(
  Object.entries(errorTemplates).map(([key, value]) => [
    key,
    createErrorTemplate(key as ErrorCodes, value),
  ]),
) as Record<ErrorCodes, ApiErrorTemplate>;

export const Errors: Record<ErrorCodes, ApiErrorTemplate> = templates;

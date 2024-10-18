import { HttpStatus } from '@nestjs/common';
import { ApiErrorTemplate } from '../interfaces';

const errorTemplates = {
  NOT_MODIFIED: {
    message: 'Resource was not modified',
    status: HttpStatus.NOT_MODIFIED, // 304
  },
  COOKIE_TOKEN_MISSING: {
    message: 'Cookie token not found in request',
    status: HttpStatus.BAD_REQUEST, // 400
  },
  EMAIL_CONFIRMATION_INVALID: {
    message: 'Invalid email confirmation code or link',
    status: HttpStatus.BAD_REQUEST, // 400
  },
  EMAIL_TOKEN_INVALID: {
    message: 'Invalid email token',
    status: HttpStatus.BAD_REQUEST, // 400
  },
  MFA_ALREADY_PASSED: {
    message: 'Multi-factor authentication already passed',
    status: HttpStatus.BAD_REQUEST, // 400
  },
  API_TOKENS_LIMIT_REACHED: {
    message: 'Maximum API tokens limit reached for the user',
    status: HttpStatus.BAD_REQUEST, // 400
  },
  CAPTCHA_REQUIRED: {
    message: 'Captcha required',
    status: HttpStatus.BAD_REQUEST, // 400
  },
  CAPTCHA_INVALID_OR_EXPIRED: {
    message: 'Captcha is invalid or expired',
    status: HttpStatus.BAD_REQUEST, // 400
  },
  INVALID_RESET_PASSWORD_TOKEN: {
    message: 'Invalid or expired reset password token',
    status: HttpStatus.BAD_REQUEST, // 400
  },
  NEW_PASSWORD_FIELD_SAME_WITH_OLD: {
    message:
      'New password field must be different from the old password field in request body',
    status: HttpStatus.BAD_REQUEST, // 400
  },
  JWT_TOKEN_INVALID: {
    message: 'JWT token is invalid',
    status: HttpStatus.UNAUTHORIZED, // 401
  },
  JWT_TOKEN_INACTIVE: {
    message: 'JWT token is inactive, refresh is required',
    status: HttpStatus.UNAUTHORIZED, // 401
  },
  INVALID_CREDENTIALS: {
    message: 'Invalid credentials provided',
    status: HttpStatus.UNAUTHORIZED, // 401
  },
  REFRESH_TOKEN_INVALID: {
    message: 'Refresh token is invalid',
    status: HttpStatus.UNAUTHORIZED, // 401
  },
  INVALID_TOTP: {
    message: 'Invalid TOTP code provided',
    status: HttpStatus.UNAUTHORIZED, // 401
  },
  INVALID_PASSWORD: {
    message: 'Invalid password provided',
    status: HttpStatus.FORBIDDEN, // 403
  },
  FORBIDDEN_WITH_TOKEN_LIMITS: {
    message: 'Forbidden access with current token limits',
    status: HttpStatus.FORBIDDEN, // 403
  },
  FORBIDDEN_WITH_API_TOKENS: {
    message: 'Forbidden access with API tokens',
    status: HttpStatus.FORBIDDEN, // 403
  },
  REVOKED_API_TOKEN: {
    message: 'API token was revoked',
    status: HttpStatus.FORBIDDEN, // 403
  },
  USER_NOT_FOUND: {
    message: 'User does not exist',
    status: HttpStatus.NOT_FOUND, // 404
  },
  NOT_FOUND_API_TOKEN: {
    message: 'API token not found',
    status: HttpStatus.NOT_FOUND, // 404
  },
  USER_NO_API_TOKENS: {
    message: 'User does not have any API tokens',
    status: HttpStatus.NOT_FOUND, // 404
  },
  API_TOKEN_NOT_FOUND: {
    message: 'API token not found',
    status: HttpStatus.NOT_FOUND, // 404
  },
  USER_ALREADY_EXISTS: {
    message: 'User with the same username or email already exists',
    status: HttpStatus.CONFLICT, // 409
  },
  SAME_PASSWORD: {
    message: 'New password and old password are the same',
    status: HttpStatus.CONFLICT, // 409
  },
  USER_DELETED: {
    message: 'User with the same username or email was deleted',
    status: HttpStatus.GONE, // 410
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

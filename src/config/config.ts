import * as fs from 'fs';
import * as path from 'path';
import { config as dotenvConfig } from 'dotenv';

import { AppConfig } from './config.dto';
import { validateSync } from 'class-validator';
import { plainToClass } from 'class-transformer';
import { NodeEnvTypes } from '../common/enums';

const readKeyFile = (fileName: string): string => {
  return fs.readFileSync(path.join(__dirname, '../../keys', fileName), 'utf8');
};

dotenvConfig();

const nodeEnv = process.env.NODE_ENV || 'production';
if (nodeEnv === NodeEnvTypes.DEVELOPMENT || nodeEnv === NodeEnvTypes.TEST) {
  const envFilePath = path.resolve(__dirname, `../../.env.${nodeEnv}.local`);
  dotenvConfig({ path: envFilePath, override: true });
}

const appConfig: AppConfig = {
  nodeEnv,
  title: process.env.npm_package_name || 'Authorization API',
  version: process.env.npm_package_version || '1.0.0',
  description: process.env.npm_package_description || 'Authorization API',
  port: parseInt(process.env.PORT || '3000', 10),
  ip: process.env.IP,
  mongodbUrl: process.env.MONGODB_URL,
  redisUrl: process.env.REDIS_URL || '',
  apiGatewayTokenRevokeUrl: process.env.API_GATEWAY_TOKEN_REVOKE_URL || '',
  email: {
    host: process.env.EMAIL_HOST || '',
    port: parseInt(process.env.EMAIL_PORT || '587', 10),
    from: process.env.EMAIL_FROM || '',
    user: process.env.EMAIL_USER || '',
    password: process.env.EMAIL_PASSWORD || '',
    confirmEmailFrontendUrl: process.env.CONFIRM_EMAIL_FRONTEND_URL,
  },
  security: {
    bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10),
    totpSecretSize: parseInt(process.env.TOTP_SECRET_SIZE || '20', 10),
    apiTokensLimitPerUser: parseInt(
      process.env.API_TOKENS_LIMIT_PER_USER || '5',
      10,
    ),
    jwtAccessTtl: parseInt(process.env.JWT_ACCESS_TTL || '900', 10),
    jwtRefreshTtl: parseInt(process.env.JWT_REFRESH_TTL || '604800', 10),
    totpInitTtl: parseInt(process.env.TOTP_INIT_TTL || '900', 10),
    emailConfirmCodeTtl: parseInt(
      process.env.EMAIL_CONFIRMATION_CODE_TTL || '43200',
      10,
    ),
    emailMfaCodeTtl: parseInt(process.env.EMAIL_MFA_CODE_TTL || '1800', 10),
    emailTimeToVerifyCookie: parseInt(
      process.env.EMAIL_TIME_TO_VERIFY_COOKIE || '300',
      10,
    ),
  },
  keys: {
    jwtAccessPrivateKey: readKeyFile('rsa-access.key'),
    jwtAccessPublicKey: readKeyFile('rsa-access.key.pub'),
    jwtRefreshPrivateKey: readKeyFile('rsa-refresh.key'),
    jwtRefreshPublicKey: readKeyFile('rsa-refresh.key.pub'),
    jwtApiPrivateKey: readKeyFile('rsa-api.key'),
    jwtApiPublicKey: readKeyFile('rsa-api.key.pub'),
  },
};

const validatedConfig = plainToClass(AppConfig, appConfig);
const errors = validateSync(validatedConfig, {
  skipMissingProperties: false,
});

if (errors.length) {
  throw new Error(`Configuration validation failed: ${errors}`);
}

export { validatedConfig as config };

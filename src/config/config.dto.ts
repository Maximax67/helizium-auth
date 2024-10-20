import {
  IsInt,
  IsNotEmpty,
  IsString,
  IsOptional,
  IsUrl,
  Min,
  Max,
  IsPositive,
} from 'class-validator';

class EmailConfig {
  @IsString()
  @IsNotEmpty()
  host: string;

  @IsInt()
  @Min(0)
  @Max(65535)
  port: number;

  @IsString()
  @IsNotEmpty()
  from: string;

  @IsString()
  @IsNotEmpty()
  user: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsNotEmpty()
  @IsUrl()
  confirmEmailFrontendUrl: string;

  @IsNotEmpty()
  @IsUrl()
  resetPasswordEmailFrontendUrl: string;
}

class SecurityConfig {
  @IsInt()
  @IsPositive()
  @Max(30)
  bcryptSaltRounds: number;

  @IsInt()
  @IsPositive()
  @Max(100)
  totpSecretSize: number;

  @IsInt()
  @IsPositive()
  @Max(10000)
  apiTokensLimitPerUser: number;

  @IsInt()
  @IsPositive()
  jwtAccessTtl: number;

  @IsInt()
  @IsPositive()
  jwtRefreshTtl: number;

  @IsInt()
  @IsPositive()
  totpInitTtl: number;

  @IsInt()
  @IsPositive()
  emailConfirmCodeTtl: number;

  @IsInt()
  @IsPositive()
  emailMfaCodeTtl: number;

  @IsInt()
  @IsPositive()
  emailTimeToVerifyCookie: number;

  @IsInt()
  @IsPositive()
  emailResetPasswordLinkTtl: number;

  @IsInt()
  @Min(0)
  apiTokensJtiCacheTtl: number;
}

class KeysConfig {
  @IsString()
  @IsNotEmpty()
  jwtAccessPrivateKey: string;

  @IsString()
  @IsNotEmpty()
  jwtAccessPublicKey: string;

  @IsString()
  @IsNotEmpty()
  jwtRefreshPrivateKey: string;

  @IsString()
  @IsNotEmpty()
  jwtRefreshPublicKey: string;

  @IsString()
  @IsNotEmpty()
  jwtApiPrivateKey: string;

  @IsString()
  @IsNotEmpty()
  jwtApiPublicKey: string;
}

export class AppConfig {
  @IsString()
  @IsNotEmpty()
  nodeEnv: string;

  @IsString()
  @IsNotEmpty()
  title: string;

  @IsString()
  @IsNotEmpty()
  version: string;

  @IsString()
  @IsNotEmpty()
  description: string;

  @IsInt()
  @Min(0)
  @Max(65535)
  port: number;

  @IsString()
  @IsNotEmpty()
  @IsOptional()
  ip?: string;

  @IsString()
  @IsNotEmpty()
  databaseUrl: string;

  @IsString()
  @IsNotEmpty()
  redisUrl: string;

  @IsString()
  @IsNotEmpty()
  grpcServerUrl: string;

  @IsString()
  @IsNotEmpty()
  apiGatewayTokenRevokeUrl: string;

  email: EmailConfig;
  security: SecurityConfig;
  keys: KeysConfig;
}

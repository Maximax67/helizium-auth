import { Module } from '@nestjs/common';

import { AuthModule } from '../auth';
import { UsersModule } from '../users';
import { TokensModule } from '../tokens';
import { CookiesModule } from '../cookies';
import { MailModule } from '../mail';
import { TotpModule } from '../totp';
import { RedisModule } from '../redis';

import { MfaService } from './mfa.service';
import { EmailOtpService } from './email-otp.service';
import { TotpAuthService } from './totp-auth.service';
import { MfaController } from './mfa.controller';

@Module({
  imports: [
    AuthModule,
    UsersModule,
    TokensModule,
    CookiesModule,
    MailModule,
    TotpModule,
    RedisModule,
  ],
  providers: [MfaService, EmailOtpService, TotpAuthService],
  controllers: [MfaController],
})
export class MfaModule {}

import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { MailModule } from '../mail';
import { CaptchaModule } from '../captcha';
import { CookiesModule } from '../cookies';
import { TokensModule } from '../tokens';
import { UsersModule } from '../users';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from '../users/entities';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    MailModule,
    CaptchaModule,
    CookiesModule,
    TokensModule,
    UsersModule,
  ],
  providers: [AuthService],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}

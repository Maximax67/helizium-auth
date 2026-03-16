import * as otpGenerator from 'otp-generator';
import { Injectable } from '@nestjs/common';

import { MailService } from '../mail';
import { RedisService } from '../redis';
import { EmailTemplatesEnum } from '../../common/enums';
import { APP_NAME } from '../../common/constants';
import { config } from '../../config';

@Injectable()
export class EmailOtpService {
  private readonly otpGeneratorOptions = {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
    digits: true,
  };

  private readonly otpLength = 6;

  constructor(
    private readonly mailService: MailService,
    private readonly redisService: RedisService,
  ) { }

  private buildConfirmLink(userId: string, otp: string): string {
    return config.email.confirmEmailFrontendUrl
      .replace(':userId', userId)
      .replace(':otp', otp);
  }

  private generateOtp(): string {
    return otpGenerator.generate(this.otpLength, this.otpGeneratorOptions);
  }

  private getOtpStorageKey(userId: string, otp: string): string {
    return `eotp:${userId}:${otp}`;
  }

  async sendOtp(
    userId: string,
    token: string,
    email: string,
    username: string,
    isConfirmEmail: boolean = false,
    ttl: number,
  ): Promise<string> {
    const otp = this.generateOtp();
    const storageKey = this.getOtpStorageKey(userId, otp);
    const url = this.buildConfirmLink(userId, otp);

    await this.redisService.set(storageKey, token, ttl);

    await this.mailService.sendMail(
      email,
      isConfirmEmail
        ? EmailTemplatesEnum.CONFIRM_EMAIL
        : EmailTemplatesEnum.MFA_EMAIL,
      {
        appName: APP_NAME,
        username,
        otp,
        url,
      },
    );

    return otp;
  }

  async verifyOtp(userId: string, otp: string): Promise<string | null> {
    if (!userId || !otp || otp.length !== this.otpLength) {
      return null;
    }

    const storageKey = this.getOtpStorageKey(userId, otp);
    const cookieToken = await this.redisService.get(storageKey);
    if (!cookieToken) {
      return null;
    }

    await this.redisService.delete(storageKey);

    return cookieToken;
  }

  async invalidateOtp(userId: string, otp: string): Promise<void> {
    const storageKey = this.getOtpStorageKey(userId, otp);
    await this.redisService.delete(storageKey);
  }
}

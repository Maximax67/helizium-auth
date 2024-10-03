import { nanoid } from 'nanoid';
import { Injectable } from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';

import { AuthService } from '../auth';
import { UserService } from '../users';
import { RedisService } from '../redis';
import { TokenService } from '../tokens';
import { CookieService } from '../cookies';
import { EmailOtpService } from './email-otp.service';
import { TotpAuthService } from './totp-auth.service';

import { config } from '../../config';
import { ConfirmEmailDto } from './dtos';
import { MfaInfo } from '../../common/interfaces';
import { CookieNames, TokenLimits, TokenStatuses } from '../../common/enums';
import { EmailCookieTokenStatuses } from './enums';
import { EmailTokenRedisValue } from './interfaces';

@Injectable()
export class MfaService {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService,
    private readonly redisService: RedisService,
    private readonly tokenService: TokenService,
    private readonly cookieService: CookieService,
    private readonly emailOtpService: EmailOtpService,
    private readonly totpAuthService: TotpAuthService,
  ) {}

  private getEmailTokenStorageKey(userId: string, cookieToken: string): string {
    return `ect:${userId}:${cookieToken}`; // ect = email cookie token
  }

  private getEmailCookieToken(req: FastifyRequest): string | null {
    return this.cookieService.get(req, CookieNames.EMAIL_CONFIRM_TOKEN);
  }

  private async setEmailTokenRedisValue(
    storageKey: string,
    status: EmailCookieTokenStatuses,
    otp: string,
    ttl: number,
  ): Promise<void> {
    const redisValue = `${status}:${otp}`;
    await this.redisService.set(storageKey, redisValue, ttl);
  }

  private async setEmailCookieToken(
    res: FastifyReply,
    userId: string,
    cookieToken: string,
    otp: string,
    ttl: number,
  ): Promise<void> {
    const storageKey = this.getEmailTokenStorageKey(userId, cookieToken);

    await this.setEmailTokenRedisValue(
      storageKey,
      EmailCookieTokenStatuses.NOT_CONFIRMED,
      otp,
      ttl,
    );

    this.cookieService.set(res, CookieNames.EMAIL_CONFIRM_TOKEN, cookieToken, {
      path: '/auth/mfa/email/',
      expires: new Date(
        Date.now() + (ttl + config.security.emailTimeToVerifyCookie) * 1000,
      ),
    });
  }

  private async getTokenStatusAndOtpByKey(
    tokenStorageKey: string,
  ): Promise<EmailTokenRedisValue | null> {
    const value = await this.redisService.get(tokenStorageKey);
    if (!value) {
      return null;
    }

    const [status, otp] = value.split(':', 2);

    return { status: status as EmailCookieTokenStatuses, otp };
  }

  async getAvailableMfa(userId: string): Promise<MfaInfo> {
    return this.userService.getUserMfaInfo(userId);
  }

  async changeMfaRequired(userId: string, required: boolean): Promise<void> {
    await this.userService.changeMfaRequired(userId, required);
  }

  async sendEmailCode(
    req: FastifyRequest,
    res: FastifyReply,
    userId: string,
    limits: TokenLimits,
  ): Promise<void> {
    const oldCookieToken = this.getEmailCookieToken(req);
    if (oldCookieToken) {
      const oldCookieStorageKey = this.getEmailTokenStorageKey(
        userId,
        oldCookieToken,
      );

      const value = await this.getTokenStatusAndOtpByKey(oldCookieStorageKey);
      if (value) {
        await this.emailOtpService.invalidateOtp(userId, value.otp);
      }
    }

    const user = await this.userService.getUserEmailAndUsername(userId);

    if (!user) {
      throw new Error('User not exists');
    }

    const cookieToken = nanoid();
    const isConfirmEmail = limits === TokenLimits.EMAIL_NOT_CONFIRMED;
    const ttl = isConfirmEmail
      ? config.security.emailConfirmCodeTtl
      : config.security.emailMfaCodeTtl;

    const otp = await this.emailOtpService.sendOtp(
      userId,
      cookieToken,
      user.email,
      user.username,
      isConfirmEmail,
      ttl,
    );

    await this.setEmailCookieToken(res, userId, cookieToken, otp, ttl);
  }

  async cancelEmailConfirmation(
    req: FastifyRequest,
    res: FastifyReply,
    userId: string,
  ): Promise<void> {
    const cookieToken = this.getEmailCookieToken(req);
    if (!cookieToken) {
      throw new Error('Cookie token not in request');
    }

    const storageKey = this.getEmailTokenStorageKey(userId, cookieToken);
    const redisValue = await this.getTokenStatusAndOtpByKey(storageKey);
    if (!redisValue) {
      throw new Error('Cookie token is invalid');
    }

    await this.emailOtpService.invalidateOtp(userId, redisValue.otp);
    await this.redisService.delete(storageKey);

    this.authService.deleteConfirmEmailCookie(res);
  }

  async confirmEmailCode(
    confirmEmailDto: ConfirmEmailDto,
    req: FastifyRequest,
    res: FastifyReply,
    authUserId?: string,
    jti?: string,
  ): Promise<boolean> {
    const { userId, code } = confirmEmailDto;
    const userCookieToken = this.getEmailCookieToken(req);
    const otpCookieToken = await this.emailOtpService.verifyOtp(userId, code);
    if (!otpCookieToken) {
      throw new Error('Invalid code/link');
    }

    const tokenStorageKey = this.getEmailTokenStorageKey(
      userId,
      otpCookieToken,
    );
    const redisValue = await this.getTokenStatusAndOtpByKey(tokenStorageKey);

    if (
      !redisValue ||
      redisValue.status !== EmailCookieTokenStatuses.NOT_CONFIRMED
    ) {
      throw new Error('Invalid code/link');
    }

    if (await this.userService.confirmEmailIfNotConfirmed(userId)) {
      await this.tokenService.setAllUserTokensStatus(
        userId,
        TokenStatuses.UPDATE_REQUIRED,
      );
    }

    const otp = redisValue.otp;
    if (
      userCookieToken === otpCookieToken &&
      code === otp &&
      authUserId === userId &&
      jti
    ) {
      await this.redisService.delete(tokenStorageKey);
      await this.tokenService.setTokenStatus(
        userId,
        jti,
        TokenStatuses.BECAME_ROOT,
      );
      this.authService.deleteConfirmEmailCookie(res);

      return false;
    }

    await this.setEmailTokenRedisValue(
      tokenStorageKey,
      EmailCookieTokenStatuses.CONFIRMED,
      otp,
      config.security.emailTimeToVerifyCookie,
    );

    return true;
  }

  async verifyEmailConfirm(
    req: FastifyRequest,
    res: FastifyReply,
    userId: string,
    jti: string,
  ): Promise<boolean> {
    const cookieToken = this.getEmailCookieToken(req);
    if (!cookieToken) {
      throw new Error('Cookie token not in request');
    }

    const tokenStorageKey = this.getEmailTokenStorageKey(userId, cookieToken);
    const tokenStatus = (await this.getTokenStatusAndOtpByKey(tokenStorageKey))
      ?.status;

    if (!tokenStatus) {
      throw new Error('Invalid email token');
    }

    if (tokenStatus !== EmailCookieTokenStatuses.CONFIRMED) {
      return false;
    }

    await this.redisService.delete(tokenStorageKey);
    await this.tokenService.setTokenStatus(
      userId,
      jti,
      TokenStatuses.BECAME_ROOT,
    );

    this.authService.deleteConfirmEmailCookie(res);

    return true;
  }

  async disableTotp(userId: string): Promise<void> {
    await this.totpAuthService.disableTotp(userId);
  }

  async initTotp(userId: string): Promise<string> {
    return this.totpAuthService.initTotp(userId);
  }

  async confirmTotp(
    userId: string,
    limits: TokenLimits,
    jti: string,
    token: string,
  ): Promise<void> {
    const isRoot =
      limits === TokenLimits.ROOT || limits === TokenLimits.BANNED_ROOT;

    if (!(await this.totpAuthService.validateTotp(userId, token, isRoot))) {
      throw new Error('invalid totp');
    }

    if (!isRoot) {
      await this.tokenService.setTokenStatus(
        userId,
        jti,
        TokenStatuses.BECAME_ROOT,
      );
    }
  }
}

import { compile } from 'path-to-regexp';
import { Injectable } from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';

import { MailService } from '../mail';
import { UserService } from '../users';
import { TokenService } from '../tokens';
import { CookieService } from '../cookies';

import {
  CookieNames,
  EmailTemplatesEnum,
  TokenLimits,
  TokenStatuses,
} from '../../common/enums';
import { SignInDto, SignUpDto } from '../../common/dtos';
import { Jwk, MfaInfo, Token } from '../../common/interfaces';
import { getJwks } from '../../common/helpers';
import { ApiError } from '../../common/errors';
import { APP_NAME, Errors } from '../../common/constants';
import { config } from '../../config';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly tokenService: TokenService,
    private readonly cookieService: CookieService,
    private readonly mailService: MailService,
  ) {}

  private readonly toResetPasswordLink = compile(
    config.email.resetPasswordEmailFrontendUrl,
  );

  async returnJwks(): Promise<{ keys: Jwk[] }> {
    const jwks = await getJwks();

    return { keys: Object.values(jwks) };
  }

  setTokenPairToCookies(
    res: FastifyReply,
    access: Token,
    refresh: Token,
  ): void {
    this.cookieService.set(res, CookieNames.REFRESH_TOKEN, refresh.token, {
      path: '/auth/refresh',
      expires: new Date(refresh.exp * 1000),
    });

    this.cookieService.set(res, CookieNames.ACCESS_TOKEN, access.token, {
      path: '/',
      expires: new Date(access.exp * 1000),
    });
  }

  deleteCookiesTokenPair(res: FastifyReply): void {
    this.cookieService.delete(res, CookieNames.REFRESH_TOKEN, {
      path: '/auth/refresh',
    });
    this.cookieService.delete(res, CookieNames.ACCESS_TOKEN, { path: '/' });
  }

  deleteConfirmEmailCookie(res: FastifyReply): void {
    this.cookieService.delete(res, CookieNames.EMAIL_CONFIRM_TOKEN, {
      path: '/auth/mfa/email/',
    });
  }

  async signup(signUpDto: SignUpDto, res: FastifyReply): Promise<void> {
    const userId = (await this.userService.createUser(signUpDto)).toString();
    const payload = {
      userId,
      limits: TokenLimits.EMAIL_NOT_CONFIRMED,
    };

    const { accessToken, refreshToken } =
      await this.tokenService.generateTokenPair(payload);

    this.setTokenPairToCookies(res, accessToken, refreshToken);
  }

  async sign(signInDto: SignInDto, res: FastifyReply): Promise<MfaInfo> {
    const verifiedUser = await this.userService.verifyUser(signInDto);
    if (!verifiedUser) {
      throw new ApiError(Errors.INVALID_CREDENTIALS);
    }

    const { userId, limits, mfa } = verifiedUser;
    const payload = { userId: userId.toString(), limits };
    const { accessToken, refreshToken } =
      await this.tokenService.generateTokenPair(payload);

    this.setTokenPairToCookies(res, accessToken, refreshToken);

    return mfa;
  }

  async refresh(req: FastifyRequest, res: FastifyReply): Promise<string> {
    const oldToken = this.cookieService.get(req, 'refreshToken');
    if (!oldToken) {
      this.deleteCookiesTokenPair(res);
      this.deleteConfirmEmailCookie(res);

      throw new ApiError(Errors.REFRESH_TOKEN_INVALID);
    }

    const validationResult =
      await this.tokenService.validateRefreshToken(oldToken);
    if (!validationResult) {
      this.deleteCookiesTokenPair(res);
      this.deleteConfirmEmailCookie(res);

      throw new ApiError(Errors.REFRESH_TOKEN_INVALID);
    }

    const { decoded, status } = validationResult;

    await this.tokenService.revokeTokenPair(decoded);

    const userId = decoded.userId;
    let limits = decoded.limits;

    if (status !== TokenStatuses.ACTIVE) {
      const currentLimits = await this.userService.isUserHasLimits(userId);
      if (currentLimits === null) {
        this.deleteCookiesTokenPair(res);
        this.deleteConfirmEmailCookie(res);

        throw new ApiError(Errors.REFRESH_TOKEN_INVALID);
      }

      if (status === TokenStatuses.BECAME_ROOT) {
        limits =
          limits === TokenLimits.USER_BANNED
            ? TokenLimits.BANNED_ROOT
            : TokenLimits.ROOT;
      } else {
        limits = currentLimits;
      }
    } else if (limits === TokenLimits.ROOT) {
      limits = TokenLimits.DEFAULT;
    }

    const payload = { userId, limits };
    const { accessToken, refreshToken } =
      await this.tokenService.generateTokenPair(payload);

    this.setTokenPairToCookies(res, accessToken, refreshToken);

    return accessToken.jti;
  }

  async logout(res: FastifyReply, userId: string, jti: string): Promise<void> {
    this.deleteCookiesTokenPair(res);
    this.deleteConfirmEmailCookie(res);
    await this.tokenService.revokeUserTokenByJti(userId, jti);
  }

  async terminate(res: FastifyReply, userId: string): Promise<void> {
    await this.tokenService.revokeAllUserTokens(userId);
    this.deleteCookiesTokenPair(res);
    this.deleteConfirmEmailCookie(res);
  }

  async requestPasswordChange(email: string): Promise<void> {
    const user = await this.userService.getIdAndUsernameByEmail(email);
    if (user) {
      const username = user.username;
      const userId = user.id.toString('hex');

      const resetPasswordToken =
        await this.tokenService.generateResetPasswordToken(userId);

      await this.mailService.sendMail(
        email,
        EmailTemplatesEnum.RESET_PASSWORD,
        {
          appName: APP_NAME,
          username,
          url: this.toResetPasswordLink({ userId, token: resetPasswordToken }),
        },
      );
    }
  }

  async verifyPasswordChangeToken(
    userId: string,
    token: string,
  ): Promise<void> {
    if (!(await this.tokenService.validateResetPasswordToken(userId, token))) {
      throw new ApiError(Errors.INVALID_RESET_PASSWORD_TOKEN);
    }
  }

  async confirmPasswordChange(
    res: FastifyReply,
    userId: string,
    token: string,
    newPassword: string,
  ): Promise<void> {
    await this.verifyPasswordChangeToken(userId, token);
    await this.userService.setNewPasswordIfNotTheSame(userId, newPassword);
    await this.tokenService.revokeResetPasswordToken(userId);
    await this.terminate(res, userId);
  }

  async changeUserPassword(
    res: FastifyReply,
    userId: string,
    oldPassword: string,
    newPassword: string,
  ): Promise<void> {
    await this.userService.changePassword(userId, oldPassword, newPassword);
    await this.tokenService.revokeResetPasswordToken(userId);
    await this.terminate(res, userId);
  }
}

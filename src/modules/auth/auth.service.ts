import { Injectable } from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';

import { UserService } from '../users';
import { TokenService } from '../tokens';
import { CookieService } from '../cookies';

import { CookieNames, TokenLimits, TokenStatuses } from '../../common/enums';
import { SignInDto, SignUpDto } from '../../common/dtos';
import { Jwk, MfaInfo, Token } from '../../common/interfaces';
import { getJwks } from '../../common/helpers';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly tokenService: TokenService,
    private readonly cookieService: CookieService,
  ) {}

  async returnJwks(): Promise<{ keys: Jwk[] }> {
    const jwks = await getJwks();
    return { keys: Object.values(jwks) };
  }

  setTokenPairToCookies(res: FastifyReply, access: Token, refresh: Token) {
    this.cookieService.set(res, CookieNames.REFRESH_TOKEN, refresh.token, {
      path: '/auth/refresh',
      expires: new Date(refresh.exp * 1000),
    });

    this.cookieService.set(res, CookieNames.ACCESS_TOKEN, access.token, {
      path: '/',
      expires: new Date(access.exp * 1000),
    });
  }

  deleteCookiesTokenPair(res: FastifyReply) {
    this.cookieService.delete(res, CookieNames.REFRESH_TOKEN, {
      path: '/auth/refresh',
    });
    this.cookieService.delete(res, CookieNames.ACCESS_TOKEN, { path: '/' });
  }

  deleteConfirmEmailCookie(res: FastifyReply) {
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
      //throw ApiError.fromTemplate(ApiErrorTemplates.InvalidCredentials);
      throw new Error('inv cred');
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

      throw new Error('t inv');
    }

    const validationResult =
      await this.tokenService.validateRefreshToken(oldToken);
    if (!validationResult) {
      this.deleteCookiesTokenPair(res);
      this.deleteConfirmEmailCookie(res);

      throw new Error('t inv');
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
        //throw ApiError.fromTemplate(ApiErrorTemplates.JWTTokenInvalid);
        throw new Error('t inv');
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
}

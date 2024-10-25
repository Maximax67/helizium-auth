import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UserService } from '../users';
import { TokenService } from '../tokens';
import { CookieService } from '../cookies';
import { FastifyReply, FastifyRequest } from 'fastify';
import {
  CookieNames,
  TokenLimits,
  TokenStatuses,
  TokenTypes,
} from '../../common/enums';
import { SignInDto, SignUpDto } from '../../common/dtos';
import { getJwks } from '../../common/helpers';
import { VerifiedUser } from '../users/interfaces';
import { Errors } from '../../common/constants';
import { MailService } from '../mail';
import { ApiError } from '../../common/errors';

jest.mock('../../common/helpers', () => ({
  getJwks: jest.fn(),
}));

describe('AuthService', () => {
  let authService: AuthService;
  let userService: UserService;
  let tokenService: TokenService;
  let cookieService: CookieService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UserService,
          useValue: {
            createUser: jest.fn(),
            verifyUser: jest.fn(),
            isUserHasLimits: jest.fn(),
            setNewPasswordIfNotTheSame: jest.fn(),
            changePassword: jest.fn(),
          },
        },
        {
          provide: TokenService,
          useValue: {
            generateTokenPair: jest.fn(),
            validateRefreshToken: jest.fn(),
            revokeTokenPair: jest.fn(),
            revokeUserTokenByJti: jest.fn(),
            revokeAllUserTokens: jest.fn(),
            validateResetPasswordToken: jest.fn(),
            revokeResetPasswordToken: jest.fn(),
          },
        },
        {
          provide: CookieService,
          useValue: {
            set: jest.fn(),
            get: jest.fn(),
            delete: jest.fn(),
          },
        },
        {
          provide: MailService,
          useValue: {},
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    userService = module.get<UserService>(UserService);
    tokenService = module.get<TokenService>(TokenService);
    cookieService = module.get<CookieService>(CookieService);
  });

  it('should be defined', () => {
    expect(authService).toBeDefined();
  });

  describe('AuthService', () => {
    it('should define returnJwks()', () => {
      expect(authService.returnJwks).toBeDefined();
      expect(typeof authService.returnJwks).toBe('function');
    });

    it('should define setTokenPairToCookies()', () => {
      expect(authService.setTokenPairToCookies).toBeDefined();
      expect(typeof authService.setTokenPairToCookies).toBe('function');
    });

    it('should define revokeCookiesTokenPair()', () => {
      expect(authService.deleteCookiesTokenPair).toBeDefined();
      expect(typeof authService.deleteCookiesTokenPair).toBe('function');
    });

    it('should define signup()', () => {
      expect(authService.signup).toBeDefined();
      expect(typeof authService.signup).toBe('function');
    });

    it('should define sign()', () => {
      expect(authService.sign).toBeDefined();
      expect(typeof authService.sign).toBe('function');
    });

    it('should define refresh()', () => {
      expect(authService.refresh).toBeDefined();
      expect(typeof authService.refresh).toBe('function');
    });

    it('should define logout()', () => {
      expect(authService.logout).toBeDefined();
      expect(typeof authService.logout).toBe('function');
    });

    it('should define terminate()', () => {
      expect(authService.terminate).toBeDefined();
      expect(typeof authService.terminate).toBe('function');
    });
  });

  describe('returnJwks', () => {
    it('should return JWKS', async () => {
      const mockJwks = { key1: { kty: 'RSA' }, key2: { kty: 'EC' } };
      (getJwks as jest.Mock).mockResolvedValue(mockJwks);

      const result = await authService.returnJwks();
      expect(result).toEqual({ keys: Object.values(mockJwks) });
      expect(getJwks).toHaveBeenCalled();
    });
  });

  describe('setTokenPairToCookies', () => {
    it('should set access and refresh tokens in cookies', () => {
      const res = {} as FastifyReply;

      const accessToken = {
        token: 'access-token',
        kid: 'kid1',
        type: TokenTypes.ACCESS,
        limits: TokenLimits.DEFAULT,
        jti: 'jti1',
        userId: 'userId',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      };

      const refreshToken = {
        token: 'refresh-token',
        kid: 'kid2',
        type: TokenTypes.REFRESH,
        limits: TokenLimits.DEFAULT,
        jti: 'jti2',
        userId: 'userId',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 7200,
      };

      authService.setTokenPairToCookies(res, accessToken, refreshToken);

      expect(cookieService.set).toHaveBeenCalledWith(
        res,
        CookieNames.REFRESH_TOKEN,
        refreshToken.token,
        {
          path: '/auth/refresh',
          expires: new Date(refreshToken.exp * 1000),
        },
      );

      expect(cookieService.set).toHaveBeenCalledWith(
        res,
        CookieNames.ACCESS_TOKEN,
        accessToken.token,
        {
          path: '/',
          expires: new Date(accessToken.exp * 1000),
        },
      );
    });
  });

  describe('revokeCookiesTokenPair', () => {
    it('should revoke access and refresh tokens from cookies', () => {
      const res = {} as FastifyReply;

      authService.deleteCookiesTokenPair(res);

      expect(cookieService.delete).toHaveBeenCalledWith(res, 'refreshToken', {
        path: '/auth/refresh',
      });
      expect(cookieService.delete).toHaveBeenCalledWith(res, 'accessToken', {
        path: '/',
      });
    });
  });

  describe('signup', () => {
    it('should create a user and set tokens in cookies', async () => {
      const signUpDto: SignUpDto = {
        username: 'test',
        email: 'test@test.com',
        password: 'pass123',
      };
      const res = {} as FastifyReply;

      jest.spyOn(userService, 'createUser').mockResolvedValue('userId');
      jest.spyOn(tokenService, 'generateTokenPair').mockResolvedValue({
        accessToken: {
          token: 'access-token',
          kid: 'kid1',
          type: TokenTypes.ACCESS,
          limits: TokenLimits.DEFAULT,
          jti: 'jti1',
          userId: 'userId',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        refreshToken: {
          token: 'refresh-token',
          kid: 'kid2',
          type: TokenTypes.REFRESH,
          limits: TokenLimits.DEFAULT,
          jti: 'jti2',
          userId: 'userId',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 7200,
        },
      });

      await authService.signup(signUpDto, res);

      expect(userService.createUser).toHaveBeenCalledWith(signUpDto);
      expect(tokenService.generateTokenPair).toHaveBeenCalledWith({
        userId: expect.any(String),
        limits: TokenLimits.EMAIL_NOT_CONFIRMED,
      });
      expect(cookieService.set).toHaveBeenCalled();
    });
  });

  describe('sign', () => {
    it('should verify user, generate tokens and return MFA info', async () => {
      const signInDto: SignInDto = {
        login: 'test@test.com',
        password: 'pass123',
      };
      const res = {} as FastifyReply;

      const mockVerifiedUser = {
        userId: 'userId',
        limits: TokenLimits.DEFAULT,
        mfa: { required: true },
      };
      jest
        .spyOn(userService, 'verifyUser')
        .mockResolvedValue(mockVerifiedUser as VerifiedUser);
      jest.spyOn(tokenService, 'generateTokenPair').mockResolvedValue({
        accessToken: {
          token: 'access-token',
          kid: 'kid1',
          type: TokenTypes.ACCESS,
          limits: TokenLimits.DEFAULT,
          jti: 'jti1',
          userId: 'userId',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        refreshToken: {
          token: 'refresh-token',
          kid: 'kid2',
          type: TokenTypes.REFRESH,
          limits: TokenLimits.DEFAULT,
          jti: 'jti2',
          userId: 'userId',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 7200,
        },
      });

      const result = await authService.sign(signInDto, res);

      expect(userService.verifyUser).toHaveBeenCalledWith(signInDto);
      expect(tokenService.generateTokenPair).toHaveBeenCalledWith({
        userId: expect.any(String),
        limits: TokenLimits.DEFAULT,
      });
      expect(cookieService.set).toHaveBeenCalled();
      expect(result).toEqual(mockVerifiedUser.mfa);
    });

    it('should throw error if user verification fails', async () => {
      const signInDto: SignInDto = {
        login: 'test@test.com',
        password: 'pass123',
      };
      jest.spyOn(userService, 'verifyUser').mockResolvedValue(null);

      await expect(
        authService.sign(signInDto, {} as FastifyReply),
      ).rejects.toThrow(Errors.INVALID_CREDENTIALS.message);
    });
  });

  describe('refresh', () => {
    it('should refresh token and set new tokens in cookies', async () => {
      const req = {} as FastifyRequest;
      const res = {} as FastifyReply;
      jest.spyOn(cookieService, 'get').mockReturnValue('refresh-token');
      jest.spyOn(tokenService, 'validateRefreshToken').mockResolvedValue({
        decoded: {
          token: 'refresh-token',
          kid: 'kid1',
          type: TokenTypes.REFRESH,
          limits: TokenLimits.DEFAULT,
          jti: 'jti1',
          userId: 'userId',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 7200,
        },
        status: TokenStatuses.ACTIVE,
      });
      jest.spyOn(tokenService, 'generateTokenPair').mockResolvedValue({
        accessToken: {
          token: 'new-access-token',
          kid: 'kid2',
          type: TokenTypes.ACCESS,
          limits: TokenLimits.DEFAULT,
          jti: 'jti2',
          userId: 'userId',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        refreshToken: {
          token: 'new-refresh-token',
          kid: 'kid3',
          type: TokenTypes.REFRESH,
          limits: TokenLimits.DEFAULT,
          jti: 'jti3',
          userId: 'userId',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 7200,
        },
      });

      const result = await authService.refresh(req, res);

      expect(cookieService.get).toHaveBeenCalledWith(req, 'refreshToken');
      expect(tokenService.validateRefreshToken).toHaveBeenCalledWith(
        'refresh-token',
      );
      expect(tokenService.generateTokenPair).toHaveBeenCalledWith({
        userId: 'userId',
        limits: TokenLimits.DEFAULT,
      });
      expect(result).toBe('jti2');
    });

    it('should throw error if refresh token is invalid', async () => {
      const req = {} as FastifyRequest;
      const res = {} as FastifyReply;
      jest.spyOn(cookieService, 'get').mockReturnValue(null);

      await expect(authService.refresh(req, res)).rejects.toThrow(
        Errors.REFRESH_TOKEN_INVALID.message,
      );
    });
  });

  describe('logout', () => {
    it('should revoke tokens and remove cookies', async () => {
      const res = {} as FastifyReply;
      jest
        .spyOn(tokenService, 'revokeUserTokenByJti')
        .mockResolvedValue(undefined);

      await authService.logout(res, 'userId', 'jti');

      expect(cookieService.delete).toHaveBeenCalled();
      expect(tokenService.revokeUserTokenByJti).toHaveBeenCalledWith(
        'userId',
        'jti',
      );
    });
  });

  describe('terminate', () => {
    it('should revoke all tokens and remove cookies', async () => {
      const res = {} as FastifyReply;
      jest
        .spyOn(tokenService, 'revokeAllUserTokens')
        .mockResolvedValue(undefined);

      await authService.terminate(res, 'userId');

      expect(cookieService.delete).toHaveBeenCalled();
      expect(tokenService.revokeAllUserTokens).toHaveBeenCalledWith('userId');
    });
  });

  describe('verifyPasswordChangeToken', () => {
    it('should throw an error if the token is invalid', async () => {
      (tokenService.validateResetPasswordToken as jest.Mock).mockResolvedValue(
        false,
      );
      await expect(
        authService.verifyPasswordChangeToken('userId', 'invalidToken'),
      ).rejects.toThrow(ApiError);
      expect(tokenService.validateResetPasswordToken).toHaveBeenCalledWith(
        'userId',
        'invalidToken',
      );
    });

    it('should not throw an error if the token is valid', async () => {
      (tokenService.validateResetPasswordToken as jest.Mock).mockResolvedValue(
        true,
      );
      await expect(
        authService.verifyPasswordChangeToken('userId', 'validToken'),
      ).resolves.not.toThrow();
      expect(tokenService.validateResetPasswordToken).toHaveBeenCalledWith(
        'userId',
        'validToken',
      );
    });
  });

  describe('confirmPasswordChange', () => {
    it('should verify token, update password, and terminate session', async () => {
      const res = {} as FastifyReply;

      (tokenService.validateResetPasswordToken as jest.Mock).mockResolvedValue(
        true,
      );
      (userService.setNewPasswordIfNotTheSame as jest.Mock).mockResolvedValue(
        true,
      );

      await authService.confirmPasswordChange(
        res,
        'userId',
        'token',
        'newPassword',
      );

      expect(tokenService.validateResetPasswordToken).toHaveBeenCalledWith(
        'userId',
        'token',
      );
      expect(userService.setNewPasswordIfNotTheSame).toHaveBeenCalledWith(
        'userId',
        'newPassword',
      );
      expect(tokenService.revokeResetPasswordToken).toHaveBeenCalledWith(
        'userId',
      );
    });
  });

  describe('changeUserPassword', () => {
    it('should change password and terminate user session', async () => {
      const res = {} as FastifyReply;
      await authService.changeUserPassword(
        res,
        'userId',
        'oldPassword',
        'newPassword',
      );

      expect(userService.changePassword).toHaveBeenCalledWith(
        'userId',
        'oldPassword',
        'newPassword',
      );
      expect(tokenService.revokeResetPasswordToken).toHaveBeenCalledWith(
        'userId',
      );
    });
  });
});

import { Test, TestingModule } from '@nestjs/testing';
import { FastifyReply, FastifyRequest } from 'fastify';
import { nanoid } from 'nanoid';
import { MfaService } from './mfa.service';
import { AuthService } from '../auth';
import { UserService } from '../users';
import { RedisService } from '../redis';
import { TokenService } from '../tokens';
import { CookieService } from '../cookies';
import { EmailOtpService } from './email-otp.service';
import { TotpAuthService } from './totp-auth.service';
import { ConfirmEmailDto } from './dtos';
import { EmailCookieTokenStatuses } from './enums';
import { TokenLimits, TokenStatuses, CookieNames } from '../../common/enums';
import { config } from '../../config';

jest.mock('nanoid');

describe('MfaService', () => {
  let mfaService: MfaService;
  let authService: AuthService;
  let userService: UserService;
  let redisService: RedisService;
  let tokenService: TokenService;
  let cookieService: CookieService;
  let emailOtpService: EmailOtpService;
  let totpAuthService: TotpAuthService;
  let mockReq: FastifyRequest;
  let mockRes: FastifyReply;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MfaService,
        {
          provide: AuthService,
          useValue: {
            deleteConfirmEmailCookie: jest.fn(),
          },
        },
        {
          provide: UserService,
          useValue: {
            getUserMfaInfo: jest.fn(),
            changeMfaRequired: jest.fn(),
            getUserById: jest.fn(),
            confirmEmailIfNotConfirmed: jest.fn(),
          },
        },
        {
          provide: RedisService,
          useValue: {
            set: jest.fn(),
            get: jest.fn(),
            delete: jest.fn(),
          },
        },
        {
          provide: TokenService,
          useValue: {
            setAllUserTokensStatus: jest.fn(),
            setTokenStatus: jest.fn(),
          },
        },
        {
          provide: CookieService,
          useValue: {
            set: jest.fn(),
            get: jest.fn(),
          },
        },
        {
          provide: EmailOtpService,
          useValue: {
            sendOtp: jest.fn(),
            verifyOtp: jest.fn(),
            invalidateOtp: jest.fn(),
          },
        },
        {
          provide: TotpAuthService,
          useValue: {
            disableTotp: jest.fn(),
            initTotp: jest.fn(),
            validateTotp: jest.fn(),
          },
        },
      ],
    }).compile();

    mfaService = module.get<MfaService>(MfaService);
    authService = module.get<AuthService>(AuthService);
    userService = module.get<UserService>(UserService);
    redisService = module.get<RedisService>(RedisService);
    tokenService = module.get<TokenService>(TokenService);
    cookieService = module.get<CookieService>(CookieService);
    emailOtpService = module.get<EmailOtpService>(EmailOtpService);
    totpAuthService = module.get<TotpAuthService>(TotpAuthService);

    mockReq = {
      cookies: {},
    } as FastifyRequest;

    mockRes = {
      set: jest.fn(),
    } as unknown as FastifyReply;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(mfaService).toBeDefined();
  });

  describe('MfaService', () => {
    it('should define getAvailableMfa()', () => {
      expect(mfaService.getAvailableMfa).toBeDefined();
      expect(typeof mfaService.getAvailableMfa).toBe('function');
    });

    it('should define changeMfaRequired()', () => {
      expect(mfaService.changeMfaRequired).toBeDefined();
      expect(typeof mfaService.changeMfaRequired).toBe('function');
    });

    it('should define cancelEmailConfirmation()', () => {
      expect(mfaService.cancelEmailConfirmation).toBeDefined();
      expect(typeof mfaService.cancelEmailConfirmation).toBe('function');
    });

    it('should define sendEmailCode()', () => {
      expect(mfaService.sendEmailCode).toBeDefined();
      expect(typeof mfaService.sendEmailCode).toBe('function');
    });

    it('should define confirmEmailCode()', () => {
      expect(mfaService.confirmEmailCode).toBeDefined();
      expect(typeof mfaService.confirmEmailCode).toBe('function');
    });

    it('should define verifyEmailConfirm()', () => {
      expect(mfaService.verifyEmailConfirm).toBeDefined();
      expect(typeof mfaService.verifyEmailConfirm).toBe('function');
    });

    it('should define disableTotp()', () => {
      expect(mfaService.disableTotp).toBeDefined();
      expect(typeof mfaService.disableTotp).toBe('function');
    });

    it('should define initTotp()', () => {
      expect(mfaService.initTotp).toBeDefined();
      expect(typeof mfaService.initTotp).toBe('function');
    });
  });

  describe('getEmailTokenStorageKey', () => {
    it('should return the correct email token storage key', () => {
      const userId = 'user123';
      const cookieToken = 'token456';
      const expectedKey = `ect:${userId}:${cookieToken}`;

      const result = mfaService['getEmailTokenStorageKey'](userId, cookieToken);

      expect(result).toBe(expectedKey);
    });
  });

  describe('getEmailCookieToken', () => {
    it('should return the email confirmation token from cookies', () => {
      const mockRequest = {
        cookies: {
          [CookieNames.EMAIL_CONFIRM_TOKEN]: 'testCookieToken',
        },
      } as unknown as FastifyRequest;

      (cookieService.get as jest.Mock).mockReturnValue('testCookieToken');

      const result = mfaService['getEmailCookieToken'](mockRequest);

      expect(result).toBe('testCookieToken');
      expect(cookieService.get).toHaveBeenCalledWith(
        mockRequest,
        CookieNames.EMAIL_CONFIRM_TOKEN,
      );
    });

    it('should return null if the email confirmation token is not in cookies', () => {
      const mockRequest = {} as FastifyRequest;

      (cookieService.get as jest.Mock).mockReturnValue(null);

      const result = mfaService['getEmailCookieToken'](mockRequest);

      expect(result).toBeNull();
      expect(cookieService.get).toHaveBeenCalledWith(
        mockRequest,
        CookieNames.EMAIL_CONFIRM_TOKEN,
      );
    });
  });

  describe('setEmailTokenRedisValue', () => {
    it('should store the correct value in Redis with a TTL', async () => {
      const storageKey = 'ect:user123:token456';
      const status = EmailCookieTokenStatuses.NOT_CONFIRMED;
      const otp = '123456';
      const ttl = 3600;
      const expectedRedisValue = `${status}:${otp}`;

      await mfaService['setEmailTokenRedisValue'](storageKey, status, otp, ttl);

      expect(redisService.set).toHaveBeenCalledWith(
        storageKey,
        expectedRedisValue,
        ttl,
      );
    });
  });

  describe('setEmailCookieToken', () => {
    it('should store the email token in Redis and set the cookie in response', async () => {
      const mockResponse = {
        setCookie: jest.fn(),
      } as unknown as FastifyReply;
      const userId = 'user123';
      const cookieToken = 'token456';
      const otp = '123456';
      const ttl = 3600;
      const storageKey = `ect:${userId}:${cookieToken}`;

      jest
        .spyOn<any, any>(mfaService as any, 'getEmailTokenStorageKey')
        .mockReturnValue(storageKey);

      await mfaService['setEmailCookieToken'](
        mockResponse,
        userId,
        cookieToken,
        otp,
        ttl,
      );

      expect(redisService.set).toHaveBeenCalledWith(
        storageKey,
        `${EmailCookieTokenStatuses.NOT_CONFIRMED}:${otp}`,
        ttl,
      );

      expect(cookieService.set).toHaveBeenCalledWith(
        mockResponse,
        CookieNames.EMAIL_CONFIRM_TOKEN,
        cookieToken,
        {
          path: '/auth/mfa/email/',
          expires: expect.any(Date),
        },
      );

      const expiresDate = (cookieService.set as jest.Mock).mock.calls[0][3]
        .expires as Date;
      expect(expiresDate.getTime()).toBeGreaterThan(Date.now());
    });
  });

  describe('getTokenStatusAndOtpByKey', () => {
    it('should return null if the value is not found in Redis', async () => {
      const tokenStorageKey = 'ect:user123:token456';

      (redisService.get as jest.Mock).mockResolvedValue(null);

      const result =
        await mfaService['getTokenStatusAndOtpByKey'](tokenStorageKey);

      expect(result).toBeNull();
      expect(redisService.get).toHaveBeenCalledWith(tokenStorageKey);
    });

    it('should return the correct status and OTP if value exists in Redis', async () => {
      const tokenStorageKey = 'ect:user123:token456';
      const redisValue = `${EmailCookieTokenStatuses.NOT_CONFIRMED}:123456`;

      (redisService.get as jest.Mock).mockResolvedValue(redisValue);

      const result =
        await mfaService['getTokenStatusAndOtpByKey'](tokenStorageKey);

      expect(result).toEqual({
        status: EmailCookieTokenStatuses.NOT_CONFIRMED,
        otp: '123456',
      });
      expect(redisService.get).toHaveBeenCalledWith(tokenStorageKey);
    });

    it('should handle unexpected Redis value format gracefully', async () => {
      const tokenStorageKey = 'ect:user123:token456';
      const invalidRedisValue = 'invalidformat';

      (redisService.get as jest.Mock).mockResolvedValue(invalidRedisValue);

      const result =
        await mfaService['getTokenStatusAndOtpByKey'](tokenStorageKey);

      expect(result).toStrictEqual({ otp: undefined, status: 'invalidformat' });
      expect(redisService.get).toHaveBeenCalledWith(tokenStorageKey);
    });
  });

  describe('getAvailableMfa', () => {
    it('should return the MFA information from the userService', async () => {
      const userId = 'user123';
      const mfaInfo = { totpEnabled: true, emailMfaEnabled: false };

      (userService.getUserMfaInfo as jest.Mock).mockResolvedValue(mfaInfo);

      const result = await mfaService.getAvailableMfa(userId);

      expect(result).toEqual(mfaInfo);
      expect(userService.getUserMfaInfo).toHaveBeenCalledWith(userId);
    });

    it('should handle cases where no MFA info is available', async () => {
      const userId = 'user123';

      (userService.getUserMfaInfo as jest.Mock).mockResolvedValue(null);

      const result = await mfaService.getAvailableMfa(userId);

      expect(result).toBeNull();
      expect(userService.getUserMfaInfo).toHaveBeenCalledWith(userId);
    });
  });

  describe('changeMfaRequired', () => {
    it('should call userService to change MFA required status', async () => {
      const userId = 'user123';
      const required = true;

      await mfaService.changeMfaRequired(userId, required);

      expect(userService.changeMfaRequired).toHaveBeenCalledWith(
        userId,
        required,
      );
    });

    it('should handle the case when changing MFA required fails', async () => {
      const userId = 'user123';
      const required = true;

      (userService.changeMfaRequired as jest.Mock).mockRejectedValue(
        new Error('Failed to change MFA status'),
      );

      await expect(
        mfaService.changeMfaRequired(userId, required),
      ).rejects.toThrow('Failed to change MFA status');
      expect(userService.changeMfaRequired).toHaveBeenCalledWith(
        userId,
        required,
      );
    });
  });

  describe('cancelEmailConfirmation', () => {
    it('should cancel email confirmation and delete Redis data', async () => {
      const mockRequest = {} as FastifyRequest;
      const mockResponse = {} as FastifyReply;
      const userId = 'user123';
      const cookieToken = 'cookieToken';

      (cookieService.get as jest.Mock).mockReturnValue(cookieToken);
      jest
        .spyOn<any, any>(mfaService as any, 'getEmailTokenStorageKey')
        .mockReturnValue('redisKey');
      (redisService.get as jest.Mock).mockResolvedValue(
        `${EmailCookieTokenStatuses.NOT_CONFIRMED}:123456`,
      );
      (redisService.delete as jest.Mock).mockResolvedValue(null);
      (emailOtpService.invalidateOtp as jest.Mock).mockResolvedValue(null);
      (authService.deleteConfirmEmailCookie as jest.Mock).mockResolvedValue(
        null,
      );

      await mfaService.cancelEmailConfirmation(
        mockRequest,
        mockResponse,
        userId,
      );

      expect(cookieService.get).toHaveBeenCalledWith(
        mockRequest,
        CookieNames.EMAIL_CONFIRM_TOKEN,
      );
      expect(redisService.get).toHaveBeenCalledWith('redisKey');
      expect(emailOtpService.invalidateOtp).toHaveBeenCalledWith(
        userId,
        '123456',
      );
      expect(redisService.delete).toHaveBeenCalledWith('redisKey');
      expect(authService.deleteConfirmEmailCookie).toHaveBeenCalledWith(
        mockResponse,
      );
    });

    it('should throw an error if cookie token is missing in the request', async () => {
      const mockRequest = {} as FastifyRequest;
      const mockResponse = {} as FastifyReply;
      const userId = 'user123';

      (cookieService.get as jest.Mock).mockReturnValue(null);

      await expect(
        mfaService.cancelEmailConfirmation(mockRequest, mockResponse, userId),
      ).rejects.toThrow('Cookie token not in request');

      expect(cookieService.get).toHaveBeenCalledWith(
        mockRequest,
        CookieNames.EMAIL_CONFIRM_TOKEN,
      );
    });

    it('should throw an error if Redis value is invalid or missing', async () => {
      const mockRequest = {} as FastifyRequest;
      const mockResponse = {} as FastifyReply;
      const userId = 'user123';
      const cookieToken = 'cookieToken';

      (cookieService.get as jest.Mock).mockReturnValue(cookieToken);
      jest
        .spyOn<any, any>(mfaService as any, 'getEmailTokenStorageKey')
        .mockReturnValue('redisKey');
      (redisService.get as jest.Mock).mockResolvedValue(null);

      await expect(
        mfaService.cancelEmailConfirmation(mockRequest, mockResponse, userId),
      ).rejects.toThrow('Cookie token is invalid');

      expect(redisService.get).toHaveBeenCalledWith('redisKey');
    });
  });

  describe('sendEmailCode', () => {
    const userId = 'testUserId';
    const cookieToken = 'testCookieToken';
    const otp = '123456';
    const limits = TokenLimits.EMAIL_NOT_CONFIRMED;

    beforeEach(() => {
      (nanoid as jest.Mock).mockReturnValue(cookieToken);
      mockReq.cookies[CookieNames.EMAIL_CONFIRM_TOKEN] = cookieToken;
    });

    it('should send an email code and set the cookie', async () => {
      const user = { email: 'test@example.com', username: 'testUser' };
      userService.getUserById = jest.fn().mockResolvedValue(user);
      emailOtpService.sendOtp = jest.fn().mockResolvedValue(otp);
      redisService.set = jest.fn().mockResolvedValue(undefined);

      await mfaService.sendEmailCode(mockReq, mockRes, userId, limits);

      expect(userService.getUserById).toHaveBeenCalledWith(userId, {
        email: 1,
        username: 1,
      });
      expect(emailOtpService.sendOtp).toHaveBeenCalledWith(
        userId,
        cookieToken,
        user.email,
        user.username,
        true,
        config.security.emailConfirmCodeTtl,
      );
      expect(redisService.set).toHaveBeenCalled();
      expect(cookieService.set).toHaveBeenCalledWith(
        mockRes,
        CookieNames.EMAIL_CONFIRM_TOKEN,
        cookieToken,
        {
          path: '/auth/mfa/email/',
          expires: expect.any(Date),
        },
      );
    });

    it('should invalidate the old OTP if exists', async () => {
      const oldOtp = 'oldOtp';
      const oldCookieToken = 'oldCookieToken';

      mockReq.cookies[CookieNames.EMAIL_CONFIRM_TOKEN] = oldCookieToken;
      redisService.get = jest
        .fn()
        .mockResolvedValue(
          `${EmailCookieTokenStatuses.NOT_CONFIRMED}:${oldOtp}`,
        );
      emailOtpService.invalidateOtp = jest.fn().mockResolvedValue(undefined);

      const user = { email: 'test@example.com', username: 'testUser' };
      userService.getUserById = jest.fn().mockResolvedValue(user);
      emailOtpService.sendOtp = jest.fn().mockResolvedValue(otp);
      redisService.set = jest.fn().mockResolvedValue(undefined);

      await mfaService.sendEmailCode(mockReq, mockRes, userId, limits);

      expect(emailOtpService.invalidateOtp).not.toHaveBeenCalled();
    });

    it('should throw an error if the user does not exist', async () => {
      userService.getUserById = jest.fn().mockResolvedValue(null);

      await expect(
        mfaService.sendEmailCode(mockReq, mockRes, userId, limits),
      ).rejects.toThrow('User not exists');
    });
  });

  describe('confirmEmailCode', () => {
    const confirmEmailDto: ConfirmEmailDto = {
      userId: 'testUserId',
      code: 'testCode',
    };
    const mockUserId = 'testUserId';
    const mockJti = 'testJti';
    const mockOtp = 'testCode';
    const mockCookieToken = 'cookieToken';
    const tokenStorageKey = `ect:${mockUserId}:${mockCookieToken}`;

    beforeEach(() => {
      mockReq.cookies = {
        [CookieNames.EMAIL_CONFIRM_TOKEN]: mockCookieToken,
      };

      userService.confirmEmailIfNotConfirmed = jest
        .fn()
        .mockResolvedValue(true);
    });

    it('should confirm the email code successfully', async () => {
      emailOtpService.verifyOtp = jest.fn().mockResolvedValue(mockCookieToken);

      redisService.get = jest
        .fn()
        .mockResolvedValue(
          `${EmailCookieTokenStatuses.NOT_CONFIRMED}:${mockOtp}`,
        );

      (cookieService.get as jest.Mock).mockReturnValue(mockCookieToken);
      tokenService.setTokenStatus = jest.fn().mockResolvedValue(undefined);

      const result = await mfaService.confirmEmailCode(
        confirmEmailDto,
        mockReq,
        mockRes,
        mockUserId,
        mockJti,
      );

      expect(result).toBe(false);
      expect(redisService.get).toHaveBeenCalledWith(tokenStorageKey);
      expect(redisService.delete).toHaveBeenCalledWith(tokenStorageKey);
      expect(tokenService.setTokenStatus).toHaveBeenCalledWith(
        mockUserId,
        mockJti,
        TokenStatuses.BECAME_ROOT,
      );
      expect(authService.deleteConfirmEmailCookie).toHaveBeenCalledWith(
        mockRes,
      );
    });

    it('should confirm the email code successfully', async () => {
      emailOtpService.verifyOtp = jest.fn().mockResolvedValue(mockCookieToken);

      redisService.get = jest
        .fn()
        .mockResolvedValue(
          `${EmailCookieTokenStatuses.NOT_CONFIRMED}:${mockOtp}`,
        );

      (cookieService.get as jest.Mock).mockReturnValue(mockCookieToken);
      tokenService.setTokenStatus = jest.fn().mockResolvedValue(undefined);

      const result = await mfaService.confirmEmailCode(
        confirmEmailDto,
        mockReq,
        mockRes,
      );

      expect(result).toBe(true);
      expect(redisService.get).toHaveBeenCalledWith(tokenStorageKey);
    });

    it('should throw an error if the OTP is invalid', async () => {
      emailOtpService.verifyOtp = jest.fn().mockResolvedValue(null);

      await expect(
        mfaService.confirmEmailCode(confirmEmailDto, mockReq, mockRes),
      ).rejects.toThrow('Invalid code/link');
    });

    it('should throw an error if the token is invalid', async () => {
      emailOtpService.verifyOtp = jest.fn().mockResolvedValue(mockCookieToken);
      redisService.get = jest.fn().mockResolvedValue(null);

      await expect(
        mfaService.confirmEmailCode(confirmEmailDto, mockReq, mockRes),
      ).rejects.toThrow('Invalid code/link');
    });

    it('should handle the case where email confirmation is already confirmed', async () => {
      emailOtpService.verifyOtp = jest.fn().mockResolvedValue(mockCookieToken);
      redisService.get = jest
        .fn()
        .mockResolvedValue(
          `${EmailCookieTokenStatuses.NOT_CONFIRMED}:${mockOtp}`,
        );

      const result = await mfaService.confirmEmailCode(
        confirmEmailDto,
        mockReq,
        mockRes,
      );

      expect(result).toBe(true);
      expect(redisService.delete).not.toHaveBeenCalled();
    });
  });

  describe('verifyEmailConfirm', () => {
    it('should throw an error if token status is invalid', async () => {
      const mockRequest = {} as FastifyRequest;
      const mockResponse = {} as FastifyReply;
      const userId = 'user123';
      const jti = 'jti123';
      const cookieToken = 'cookieToken';

      (cookieService.get as jest.Mock).mockReturnValue(cookieToken);
      jest
        .spyOn<any, any>(mfaService as any, 'getEmailTokenStorageKey')
        .mockReturnValue('redisKey');

      jest
        .spyOn(mfaService as any, 'getTokenStatusAndOtpByKey')
        .mockResolvedValue(null);

      await expect(
        mfaService.verifyEmailConfirm(mockRequest, mockResponse, userId, jti),
      ).rejects.toThrow('Invalid email token');

      expect(cookieService.get).toHaveBeenCalledWith(
        mockRequest,
        CookieNames.EMAIL_CONFIRM_TOKEN,
      );
      expect(mfaService['getTokenStatusAndOtpByKey']).toHaveBeenCalledWith(
        'redisKey',
      );
    });

    it('should return false if the token status is not CONFIRMED', async () => {
      const mockRequest = {} as FastifyRequest;
      const mockResponse = {} as FastifyReply;
      const userId = 'user123';
      const jti = 'jti123';
      const cookieToken = 'cookieToken';

      (cookieService.get as jest.Mock).mockReturnValue(cookieToken);
      jest
        .spyOn<any, any>(mfaService as any, 'getEmailTokenStorageKey')
        .mockReturnValue('redisKey');

      jest
        .spyOn(mfaService as any, 'getTokenStatusAndOtpByKey')
        .mockResolvedValue({
          status: EmailCookieTokenStatuses.NOT_CONFIRMED,
          otp: '123456',
        });

      const result = await mfaService.verifyEmailConfirm(
        mockRequest,
        mockResponse,
        userId,
        jti,
      );

      expect(result).toBe(false);
      expect(cookieService.get).toHaveBeenCalledWith(
        mockRequest,
        CookieNames.EMAIL_CONFIRM_TOKEN,
      );
      expect(mfaService['getTokenStatusAndOtpByKey']).toHaveBeenCalledWith(
        'redisKey',
      );
    });

    it('should delete the token from Redis, set token status, and delete the cookie if the token is confirmed', async () => {
      const mockRequest = {} as FastifyRequest;
      const mockResponse = {} as FastifyReply;
      const userId = 'user123';
      const jti = 'jti123';
      const cookieToken = 'cookieToken';

      (cookieService.get as jest.Mock).mockReturnValue(cookieToken);
      jest
        .spyOn<any, any>(mfaService as any, 'getEmailTokenStorageKey')
        .mockReturnValue('redisKey');

      jest
        .spyOn(mfaService as any, 'getTokenStatusAndOtpByKey')
        .mockResolvedValue({
          status: EmailCookieTokenStatuses.CONFIRMED,
          otp: '123456',
        });
      (redisService.delete as jest.Mock).mockResolvedValue(null);
      (tokenService.setTokenStatus as jest.Mock).mockResolvedValue(null);
      (authService.deleteConfirmEmailCookie as jest.Mock).mockResolvedValue(
        null,
      );

      const result = await mfaService.verifyEmailConfirm(
        mockRequest,
        mockResponse,
        userId,
        jti,
      );

      expect(result).toBe(true);
      expect(redisService.delete).toHaveBeenCalledWith('redisKey');
      expect(tokenService.setTokenStatus).toHaveBeenCalledWith(
        userId,
        jti,
        TokenStatuses.BECAME_ROOT,
      );
      expect(authService.deleteConfirmEmailCookie).toHaveBeenCalledWith(
        mockResponse,
      );
    });
  });

  describe('disableTotp', () => {
    it('should call totpAuthService to disable TOTP for the user', async () => {
      const userId = 'user123';

      (totpAuthService.disableTotp as jest.Mock).mockResolvedValue(null);

      await mfaService.disableTotp(userId);

      expect(totpAuthService.disableTotp).toHaveBeenCalledWith(userId);
    });
  });

  describe('initTotp', () => {
    it('should call totpAuthService to initialize TOTP and return the result', async () => {
      const userId = 'user123';
      const secret = 'totp-secret';

      (totpAuthService.initTotp as jest.Mock).mockResolvedValue(secret);

      const result = await mfaService.initTotp(userId);

      expect(result).toBe(secret);
      expect(totpAuthService.initTotp).toHaveBeenCalledWith(userId);
    });
  });

  describe('confirmTotp', () => {
    it('should throw an error if TOTP validation fails', async () => {
      const userId = 'user123';
      const limits = TokenLimits.ROOT;
      const jti = 'jti123';
      const token = 'totp-token';

      (totpAuthService.validateTotp as jest.Mock).mockResolvedValue(false);

      await expect(
        mfaService.confirmTotp(userId, limits, jti, token),
      ).rejects.toThrow('invalid totp');

      expect(totpAuthService.validateTotp).toHaveBeenCalledWith(
        userId,
        token,
        true,
      );
    });

    it('should not set token status if the user has ROOT privileges', async () => {
      const userId = 'user123';
      const limits = TokenLimits.ROOT;
      const jti = 'jti123';
      const token = 'totp-token';

      (totpAuthService.validateTotp as jest.Mock).mockResolvedValue(true);

      await mfaService.confirmTotp(userId, limits, jti, token);

      expect(tokenService.setTokenStatus).not.toHaveBeenCalled();
    });

    it('should set token status to BECAME_ROOT if TOTP is valid and user is not ROOT', async () => {
      const userId = 'user123';
      const limits = TokenLimits.DEFAULT;
      const jti = 'jti123';
      const token = 'totp-token';

      (totpAuthService.validateTotp as jest.Mock).mockResolvedValue(true);

      await mfaService.confirmTotp(userId, limits, jti, token);

      expect(tokenService.setTokenStatus).toHaveBeenCalledWith(
        userId,
        jti,
        TokenStatuses.BECAME_ROOT,
      );
    });
  });
});

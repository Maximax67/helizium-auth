import { Test, TestingModule } from '@nestjs/testing';
import { TokenService } from './token.service';
import { RedisService } from '../redis/redis.service';
import { ApiToken } from './entities';
import * as jwt from 'jsonwebtoken';
import { getKidMapping } from '../../common/helpers';
import { TokenTypes, TokenLimits, TokenStatuses } from '../../common/enums';
import { config } from '../../config';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { nanoid } from 'nanoid';
import { ApiTokenDto } from './dtos';
import { GenerateTokenPayload } from './interfaces';
import { Errors } from '../../common/constants';

jest.mock('axios');
jest.mock('nanoid');
jest.mock('jsonwebtoken');
jest.mock('../../common/helpers', () => ({
  getKidMapping: jest.fn(),
}));

describe('TokenService', () => {
  let service: TokenService;
  let redisService: RedisService;
  let apiTokensRepository: Repository<ApiToken>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TokenService,
        {
          provide: RedisService,
          useValue: {
            set: jest.fn(),
            get: jest.fn(),
            delete: jest.fn(),
            scanByPattern: jest.fn(),
            setMany: jest.fn(),
            deleteMany: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(ApiToken),
          useValue: {
            createQueryBuilder: jest.fn(),
            insert: jest.fn(),
            findOne: jest.fn(),
            findBy: jest.fn(),
            delete: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<TokenService>(TokenService);
    redisService = module.get<RedisService>(RedisService);
    apiTokensRepository = module.get<Repository<ApiToken>>(
      getRepositoryToken(ApiToken),
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('TokenService', () => {
    it('should define generateApiToken()', () => {
      expect(service.generateApiToken).toBeDefined();
      expect(typeof service.generateApiToken).toBe('function');
    });

    it('should define validateToken()', () => {
      expect(service.validateToken).toBeDefined();
      expect(typeof service.validateToken).toBe('function');
    });

    it('should define validateApiToken()', () => {
      expect(service.validateApiToken).toBeDefined();
      expect(typeof service.validateApiToken).toBe('function');
    });

    it('should define validateRefreshToken()', () => {
      expect(service.validateRefreshToken).toBeDefined();
      expect(typeof service.validateRefreshToken).toBe('function');
    });

    it('should define getUserApiTokens()', () => {
      expect(service.getUserApiTokens).toBeDefined();
      expect(typeof service.getUserApiTokens).toBe('function');
    });

    it('should define getUserApiToken()', () => {
      expect(service.getUserApiToken).toBeDefined();
      expect(typeof service.getUserApiToken).toBe('function');
    });

    it('should define setTokenStatus()', () => {
      expect(service.setTokenStatus).toBeDefined();
      expect(typeof service.setTokenStatus).toBe('function');
    });

    it('should define setAllUserTokensStatus()', () => {
      expect(service.setAllUserTokensStatus).toBeDefined();
      expect(typeof service.setAllUserTokensStatus).toBe('function');
    });

    it('should define revokeTokenPair()', () => {
      expect(service.revokeTokenPair).toBeDefined();
      expect(typeof service.revokeTokenPair).toBe('function');
    });

    it('should define revokeAllUserTokens()', () => {
      expect(service.revokeAllUserTokens).toBeDefined();
      expect(typeof service.revokeAllUserTokens).toBe('function');
    });

    it('should define revokeAllUserApiTokens()', () => {
      expect(service.revokeAllUserApiTokens).toBeDefined();
      expect(typeof service.revokeAllUserApiTokens).toBe('function');
    });

    it('should define revokeUserTokenByJti()', () => {
      expect(service.revokeUserTokenByJti).toBeDefined();
      expect(typeof service.revokeUserTokenByJti).toBe('function');
    });

    it('should define revokeApiToken()', () => {
      expect(service.revokeApiToken).toBeDefined();
      expect(typeof service.revokeApiToken).toBe('function');
    });

    it('should define generateTokenPair()', () => {
      expect(service.generateTokenPair).toBeDefined();
      expect(typeof service.generateTokenPair).toBe('function');
    });

    it('should define getTokenRedisStatus()', () => {
      expect(service.getTokenRedisStatus).toBeDefined();
      expect(typeof service.getTokenRedisStatus).toBe('function');
    });
  });

  describe('generateTokenPair', () => {
    it('should generate both access and refresh tokens', async () => {
      const payload: GenerateTokenPayload = {
        userId: 'user-id',
        email: 'test@example.com',
      };

      const mockJti = 'test-jti';
      (nanoid as jest.Mock).mockReturnValue(mockJti);

      const mockAccessToken = {
        token: 'access-token',
        jti: mockJti,
        userId: 'user-id',
        type: TokenTypes.ACCESS,
        limits: TokenLimits.DEFAULT,
        iat: 1620000000,
        exp: 1620003600,
      };
      const mockRefreshToken = {
        token: 'refresh-token',
        jti: mockJti,
        userId: 'user-id',
        type: TokenTypes.REFRESH,
        limits: TokenLimits.DEFAULT,
        iat: 1620000000,
        exp: 1620007200,
      };

      jest
        .spyOn<any, any>(service, 'generateAccessToken')
        .mockResolvedValue(mockAccessToken);
      jest
        .spyOn<any, any>(service, 'generateRefreshToken')
        .mockResolvedValue(mockRefreshToken);

      const result = await service.generateTokenPair(payload);

      expect(nanoid).toHaveBeenCalled();
      expect(service['generateAccessToken']).toHaveBeenCalledWith({
        limits: TokenLimits.DEFAULT,
        userId: 'user-id',
        email: 'test@example.com',
        jti: mockJti,
      });
      expect(service['generateRefreshToken']).toHaveBeenCalledWith({
        limits: TokenLimits.DEFAULT,
        userId: 'user-id',
        email: 'test@example.com',
        jti: mockJti,
      });

      expect(result).toEqual({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });
    });
  });

  describe('generateApiToken', () => {
    const mockUserId = 'user123';
    const mockTitle = 'Test API Token';
    const mockJti = 'mocked-jti';
    const mockKid = 'mocked-kid';
    const mockToken = 'signed-token';

    beforeEach(() => {
      jest.spyOn(apiTokensRepository, 'createQueryBuilder').mockReturnValue({
        insert: jest.fn().mockReturnThis(),
        values: jest.fn().mockReturnThis(),
        returning: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({
          raw: [{ jti: mockJti }],
        }),
      } as any);

      (getKidMapping as jest.Mock).mockResolvedValue({
        API: mockKid,
      });

      (jwt.sign as jest.Mock).mockReturnValue(mockToken);
    });

    it('should generate an API token successfully', async () => {
      const result = await service.generateApiToken(
        mockUserId,
        mockTitle,
        true,
      );

      expect(jwt.sign).toHaveBeenCalledWith(
        {
          userId: mockUserId,
          jti: mockJti,
          limits: TokenLimits.DEFAULT,
          type: 'API',
        },
        config.keys.jwtApiPrivateKey,
        {
          algorithm: 'RS256',
          keyid: mockKid,
        },
      );

      expect(result).toBe(mockToken);
    });

    it('should generate an API token successfully', async () => {
      const result = await service.generateApiToken(
        mockUserId,
        mockTitle,
        false,
      );

      expect(jwt.sign).toHaveBeenCalledWith(
        {
          userId: mockUserId,
          jti: mockJti,
          limits: TokenLimits.READ_ONLY,
          type: 'API',
        },
        config.keys.jwtApiPrivateKey,
        {
          algorithm: 'RS256',
          keyid: mockKid,
        },
      );

      expect(result).toBe(mockToken);
    });
  });

  describe('validateToken', () => {
    it('should validate a valid access token', async () => {
      const token = 'validAccessToken';
      const decodedPayload = {
        type: TokenTypes.ACCESS,
        iat: 1620000000,
        exp: 1620003600,
        jti: 'test-jti',
        userId: 'user-id',
        limits: TokenLimits.DEFAULT,
      };

      (jwt.verify as jest.Mock).mockReturnValue(decodedPayload);
      const getTokenRedisStatusSpy = jest
        .spyOn(service, 'getTokenRedisStatus')
        .mockResolvedValue(TokenStatuses.ACTIVE);

      const result = await service.validateToken(token, false);

      expect(jwt.verify).toHaveBeenCalledWith(
        token,
        config.keys.jwtAccessPublicKey,
      );
      expect(getTokenRedisStatusSpy).toHaveBeenCalledWith(
        'user-id',
        'test-jti',
      );
      expect(result).toEqual({
        decoded: decodedPayload,
        status: TokenStatuses.ACTIVE,
      });
    });

    it('should return null if the access token is invalid (no redis status)', async () => {
      const token = 'validAccessToken';
      const decodedPayload = {
        type: TokenTypes.ACCESS,
        iat: 1620000000,
        exp: 1620003600,
        jti: 'test-jti',
        userId: 'user-id',
        limits: TokenLimits.DEFAULT,
      };

      (jwt.verify as jest.Mock).mockReturnValue(decodedPayload);
      const getTokenRedisStatusSpy = jest
        .spyOn(service, 'getTokenRedisStatus')
        .mockResolvedValue(null);

      const result = await service.validateToken(token, false);

      expect(jwt.verify).toHaveBeenCalledWith(
        token,
        config.keys.jwtAccessPublicKey,
      );
      expect(getTokenRedisStatusSpy).toHaveBeenCalledWith(
        'user-id',
        'test-jti',
      );
      expect(result).toBeNull();
    });

    it('should validate a valid API token', async () => {
      const token = 'validApiToken';
      const decodedPayload = {
        type: TokenTypes.API,
        iat: 1620000000,
        jti: 'test-jti',
        userId: 'user-id',
        limits: TokenLimits.DEFAULT,
      };

      (jwt.verify as jest.Mock).mockReturnValue(decodedPayload);

      jest.spyOn(service, 'validateApiToken').mockResolvedValue(true);

      const result = await service.validateToken(token, true);

      expect(jwt.verify).toHaveBeenCalledWith(
        token,
        config.keys.jwtApiPublicKey,
      );
      expect(service.validateApiToken).toHaveBeenCalledWith('test-jti');
      expect(result).toEqual({
        decoded: decodedPayload,
        status: TokenStatuses.ACTIVE,
      });
    });

    it('should return null if the token is invalid (no write access)', async () => {
      const token = 'validApiToken';
      const decodedPayload = {
        type: TokenTypes.API,
        iat: 1620000000,
        jti: 'test-jti',
        userId: 'user-id',
        limits: TokenLimits.DEFAULT,
      };

      (jwt.verify as jest.Mock).mockReturnValue(decodedPayload);

      jest.spyOn(service, 'validateApiToken').mockResolvedValue(false);

      const result = await service.validateToken(token, true);

      expect(jwt.verify).toHaveBeenCalledWith(
        token,
        config.keys.jwtApiPublicKey,
      );
      expect(service.validateApiToken).toHaveBeenCalledWith('test-jti');
      expect(result).toBeNull();
    });

    it('should return null if the token signature is invalid', async () => {
      const token = 'invalidToken';

      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error('invalid signature');
      });

      const result = await service.validateToken(token, false);

      expect(jwt.verify).toHaveBeenCalledWith(
        token,
        config.keys.jwtAccessPublicKey,
      );
      expect(result).toBeNull();
    });
  });

  describe('validateApiToken', () => {
    it('should validate API token from the database if cacheTtl is not set', async () => {
      (service as any).validateApiTokenInDatabase = jest
        .fn()
        .mockResolvedValue(true);

      const result = await service.validateApiToken('test-jti');

      expect(service['validateApiTokenInDatabase']).toHaveBeenCalledWith(
        'test-jti',
      );
      expect(result).toBe(true);
    });

    it('should return true if the token is found in Redis cache', async () => {
      (redisService.get as jest.Mock).mockResolvedValue('1');

      const result = await service.validateApiToken('test-jti');

      expect(redisService.get).toHaveBeenCalledWith(
        service['getApiTokenCacheStorageKey']('test-jti'),
      );
      expect(result).toBe(true);
    });

    it('should validate the token in the database, cache it, and return true if the token is valid', async () => {
      (redisService.get as jest.Mock).mockResolvedValue(null);

      (service as any).validateApiTokenInDatabase = jest
        .fn()
        .mockResolvedValue(true);

      const result = await service.validateApiToken('test-jti');

      expect(redisService.get).toHaveBeenCalledWith(
        service['getApiTokenCacheStorageKey']('test-jti'),
      );
      expect(service['validateApiTokenInDatabase']).toHaveBeenCalledWith(
        'test-jti',
      );
      expect(redisService.set).toHaveBeenCalledWith(
        service['getApiTokenCacheStorageKey']('test-jti'),
        '1',
        config.security.apiTokensJtiCacheTtl,
      );
      expect(result).toBe(true);
    });

    it('should return false if the token is not found in Redis or the database', async () => {
      (redisService.get as jest.Mock).mockResolvedValue(null);

      (service as any).validateApiTokenInDatabase = jest
        .fn()
        .mockResolvedValue(false);

      const result = await service.validateApiToken('test-jti');

      expect(redisService.get).toHaveBeenCalledWith(
        service['getApiTokenCacheStorageKey']('test-jti'),
      );
      expect(service['validateApiTokenInDatabase']).toHaveBeenCalledWith(
        'test-jti',
      );
      expect(redisService.set).not.toHaveBeenCalled();
      expect(result).toBe(false);
    });
  });

  describe('validateRefreshToken', () => {
    const mockRefreshToken = 'mocked-refresh-token';
    const mockUserId = 'user123';
    const mockJti = 'mocked-jti';
    const mockRefreshPayload = {
      userId: mockUserId,
      jti: mockJti,
      type: TokenTypes.REFRESH,
      limits: TokenLimits.DEFAULT,
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 60,
    };

    beforeEach(() => {
      jest.clearAllMocks();
    });

    it('should validate a valid refresh token and return decoded info with active status', async () => {
      (jwt.verify as jest.Mock).mockReturnValue(mockRefreshPayload);

      jest
        .spyOn(service, 'getTokenRedisStatus')
        .mockResolvedValue(TokenStatuses.ACTIVE);

      const result = await service.validateRefreshToken(mockRefreshToken);

      expect(jwt.verify).toHaveBeenCalledWith(
        mockRefreshToken,
        config.keys.jwtRefreshPublicKey,
      );

      expect(service.getTokenRedisStatus).toHaveBeenCalledWith(
        mockUserId,
        mockJti,
      );

      expect(result).toEqual({
        decoded: mockRefreshPayload,
        status: TokenStatuses.ACTIVE,
      });
    });

    it('should return null if the refresh token is invalid', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      const result = await service.validateRefreshToken(mockRefreshToken);

      expect(jwt.verify).toHaveBeenCalledWith(
        mockRefreshToken,
        config.keys.jwtRefreshPublicKey,
      );

      expect(result).toBeNull();
    });

    it('should return null if Redis status is missing or invalid for refresh token', async () => {
      (jwt.verify as jest.Mock).mockReturnValue(mockRefreshPayload);

      jest.spyOn(service, 'getTokenRedisStatus').mockResolvedValue(null);

      const result = await service.validateRefreshToken(mockRefreshToken);

      expect(service.getTokenRedisStatus).toHaveBeenCalledWith(
        mockUserId,
        mockJti,
      );

      expect(result).toBeNull();
    });

    it('should handle expired refresh tokens by returning null', async () => {
      const expiredRefreshPayload = {
        ...mockRefreshPayload,
        exp: Math.floor(Date.now() / 1000) - 60,
      };

      (jwt.verify as jest.Mock).mockReturnValue(expiredRefreshPayload);

      const result = await service.validateRefreshToken(mockRefreshToken);

      expect(jwt.verify).toHaveBeenCalledWith(
        mockRefreshToken,
        config.keys.jwtRefreshPublicKey,
      );

      expect(result).toBeNull();
    });

    it('should handle jwt.verify exceptions gracefully', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error('JWT Verification Failed');
      });

      const result = await service.validateRefreshToken(mockRefreshToken);

      expect(jwt.verify).toHaveBeenCalledWith(
        mockRefreshToken,
        config.keys.jwtRefreshPublicKey,
      );

      expect(result).toBeNull();
    });
  });

  describe('getUserApiTokens', () => {
    const mockUserId = 'user123';
    const mockApiTokens: ApiTokenDto[] = [
      {
        jti: 'token1',
        title: 'Token 1',
        writeAccess: true,
        createdAt: new Date(),
      },
      {
        jti: 'token2',
        title: 'Token 2',
        writeAccess: false,
        createdAt: new Date(),
      },
    ];

    it('should return a list of API tokens for a user', async () => {
      jest
        .spyOn(apiTokensRepository, 'findBy')
        .mockResolvedValue(mockApiTokens as ApiToken[]);
      const result = await service.getUserApiTokens(mockUserId);

      expect(apiTokensRepository.findBy).toHaveBeenCalledWith({
        userId: Buffer.from(mockUserId, 'hex'),
      });

      expect(result).toEqual(mockApiTokens);
    });

    it('should return an empty array if no tokens are found', async () => {
      jest
        .spyOn(apiTokensRepository, 'findBy')
        .mockResolvedValue([] as ApiToken[]);
      const result = await service.getUserApiTokens(mockUserId);

      expect(apiTokensRepository.findBy).toHaveBeenCalledWith({
        userId: Buffer.from(mockUserId, 'hex'),
      });

      expect(result).toEqual([]);
    });
  });

  describe('getUserApiToken', () => {
    const mockUserId = 'user123';
    const mockJti = 'token1';
    const mockApiToken: ApiTokenDto = {
      jti: 'token2',
      title: 'Token 2',
      writeAccess: false,
      createdAt: new Date(),
    };

    it('should return a specific API token if it exists', async () => {
      jest
        .spyOn(apiTokensRepository, 'findOne')
        .mockResolvedValue(mockApiToken as ApiToken);

      const result = await service.getUserApiToken(mockUserId, mockJti);

      expect(apiTokensRepository.findOne).toHaveBeenCalledWith({
        where: { jti: mockJti, userId: Buffer.from(mockUserId, 'hex') },
      });
      expect(result).toEqual(mockApiToken);
    });

    it('should throw an error when token is not found', async () => {
      jest.spyOn(apiTokensRepository, 'findOne').mockResolvedValue(null);

      await expect(
        service.getUserApiToken(mockUserId, mockJti),
      ).rejects.toThrow(Errors.API_TOKEN_NOT_FOUND.message);

      expect(apiTokensRepository.findOne).toHaveBeenCalledWith({
        where: { jti: mockJti, userId: Buffer.from(mockUserId, 'hex') },
      });
    });
  });

  describe('setTokenStatus', () => {
    const mockUserId = 'user123';
    const mockJti = 'mocked-jti';
    const mockStatus = TokenStatuses.ACTIVE;
    const mockExpires = config.security.jwtRefreshTtl;
    const mockTokenKey = `token:${mockJti}:${mockUserId}`;

    it('should set the token status in Redis with the correct expiry', async () => {
      await service.setTokenStatus(mockUserId, mockJti, mockStatus);

      expect(redisService.set).toHaveBeenCalledWith(
        mockTokenKey,
        mockStatus,
        mockExpires,
      );
    });

    it('should set the token status with a custom expiry', async () => {
      const customExpiry = 3600;

      await service.setTokenStatus(
        mockUserId,
        mockJti,
        mockStatus,
        customExpiry,
      );

      expect(redisService.set).toHaveBeenCalledWith(
        mockTokenKey,
        mockStatus,
        customExpiry,
      );
    });
  });

  describe('setAllUserTokensStatus', () => {
    const mockUserId = 'user123';
    const mockStatus = TokenStatuses.UPDATE_REQUIRED;
    const mockExpires = config.security.jwtRefreshTtl;
    const mockTokenKeys = [
      `token:jti1:${mockUserId}`,
      `token:jti2:${mockUserId}`,
    ];

    beforeEach(() => {
      jest
        .spyOn(redisService, 'scanByPattern')
        .mockResolvedValue(mockTokenKeys);
    });

    it('should set the status for all user tokens in Redis', async () => {
      await service.setAllUserTokensStatus(mockUserId, mockStatus);

      expect(redisService.scanByPattern).toHaveBeenCalledWith(
        `token:*:${mockUserId}`,
      );

      expect(redisService.setMany).toHaveBeenCalledWith([
        { key: mockTokenKeys[0], value: mockStatus, expiry: mockExpires },
        { key: mockTokenKeys[1], value: mockStatus, expiry: mockExpires },
      ]);
    });

    it('should set the status for all user tokens with a custom expiry', async () => {
      const customExpiry = 7200;

      await service.setAllUserTokensStatus(
        mockUserId,
        mockStatus,
        customExpiry,
      );

      expect(redisService.setMany).toHaveBeenCalledWith([
        { key: mockTokenKeys[0], value: mockStatus, expiry: customExpiry },
        { key: mockTokenKeys[1], value: mockStatus, expiry: customExpiry },
      ]);
    });
  });

  describe('revokeTokenPair', () => {
    it('should delete the token from Redis and revoke it for the API Gateway', async () => {
      const decoded = {
        userId: 'user123',
        jti: 'tokenJTI',
        limits: TokenLimits.DEFAULT,
      };
      const tokenStorageKey = `token:${decoded.jti}:${decoded.userId}`;

      redisService.delete = jest.fn().mockResolvedValue(undefined);

      const revokeForApiGatewaySpy = jest.spyOn<any, any>(
        service,
        'revokeForApiGateway',
      );

      await service.revokeTokenPair(decoded);

      expect(redisService.delete).toHaveBeenCalledWith(tokenStorageKey);
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(decoded.jti);
    });

    it('should handle errors during Redis deletion gracefully', async () => {
      const decoded = {
        userId: 'user123',
        jti: 'tokenJTI',
        limits: TokenLimits.DEFAULT,
      };
      const tokenStorageKey = `token:${decoded.jti}:${decoded.userId}`;

      redisService.delete = jest
        .fn()
        .mockRejectedValue(new Error('Redis error'));

      const revokeForApiGatewaySpy = jest.spyOn<any, any>(
        service,
        'revokeForApiGateway',
      );

      await expect(service.revokeTokenPair(decoded)).rejects.toThrow(
        'Redis error',
      );
      expect(redisService.delete).toHaveBeenCalledWith(tokenStorageKey);
      expect(revokeForApiGatewaySpy).not.toHaveBeenCalled();
    });

    it('should handle errors during API Gateway revocation gracefully', async () => {
      const decoded = {
        userId: 'user123',
        jti: 'tokenJTI',
        limits: TokenLimits.DEFAULT,
      };
      const tokenStorageKey = `token:${decoded.jti}:${decoded.userId}`;

      redisService.delete = jest.fn().mockResolvedValue(undefined);
      jest
        .spyOn<any, any>(service, 'revokeForApiGateway')
        .mockRejectedValue(new Error('API Gateway error'));

      await expect(service.revokeTokenPair(decoded)).rejects.toThrow(
        'API Gateway error',
      );
      expect(redisService.delete).toHaveBeenCalledWith(tokenStorageKey);
    });
  });

  describe('revokeAllUserTokens', () => {
    it('should revoke all user tokens and delete them from Redis', async () => {
      const userId = 'user123';
      const tokensPattern = `token:*:${userId}`;
      const tokenKeys = [
        `token:tokenJTI1:${userId}`,
        `token:tokenJTI2:${userId}`,
      ];

      redisService.scanByPattern = jest.fn().mockResolvedValue(tokenKeys);

      redisService.deleteMany = jest.fn().mockResolvedValue(undefined);

      const jtiValues = tokenKeys.map((key) => key.split(':')[1]);
      const revokeForApiGatewaySpy = jest
        .spyOn<any, any>(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      await service.revokeAllUserTokens(userId);

      expect(redisService.scanByPattern).toHaveBeenCalledWith(tokensPattern);
      expect(redisService.deleteMany).toHaveBeenCalledWith(tokenKeys);
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(jtiValues);
    });

    it('should handle no tokens found gracefully', async () => {
      const userId = 'user123';
      const tokensPattern = `token:*:${userId}`;

      redisService.scanByPattern = jest.fn().mockResolvedValue([]);

      redisService.deleteMany = jest.fn().mockResolvedValue(undefined);

      await service.revokeAllUserTokens(userId);

      expect(redisService.scanByPattern).toHaveBeenCalledWith(tokensPattern);
      expect(redisService.deleteMany).toHaveBeenCalledWith([]);
    });

    it('should handle errors during token deletion gracefully', async () => {
      const userId = 'user123';
      const tokensPattern = `token:*:${userId}`;
      const tokenKeys = [
        `token:tokenJTI1:${userId}`,
        `token:tokenJTI2:${userId}`,
      ];

      redisService.scanByPattern = jest.fn().mockResolvedValue(tokenKeys);

      redisService.deleteMany = jest
        .fn()
        .mockRejectedValue(new Error('Redis deletion error'));

      const revokeForApiGatewaySpy = jest.spyOn<any, any>(
        service,
        'revokeForApiGateway',
      );

      await expect(service.revokeAllUserTokens(userId)).rejects.toThrow(
        'Redis deletion error',
      );
      expect(redisService.scanByPattern).toHaveBeenCalledWith(tokensPattern);
      expect(redisService.deleteMany).toHaveBeenCalledWith(tokenKeys);
      expect(revokeForApiGatewaySpy).not.toHaveBeenCalled();
    });

    it('should handle errors during API Gateway revocation gracefully', async () => {
      const userId = 'user123';
      const tokensPattern = `token:*:${userId}`;
      const tokenKeys = [
        `token:tokenJTI1:${userId}`,
        `token:tokenJTI2:${userId}`,
      ];

      redisService.scanByPattern = jest.fn().mockResolvedValue(tokenKeys);

      redisService.deleteMany = jest.fn().mockResolvedValue(undefined);

      const jtiValues = tokenKeys.map((key) => key.split(':')[1]);
      const revokeForApiGatewaySpy = jest
        .spyOn<any, any>(service, 'revokeForApiGateway')
        .mockRejectedValue(new Error('API Gateway revocation error'));

      await expect(service.revokeAllUserTokens(userId)).rejects.toThrow(
        'API Gateway revocation error',
      );
      expect(redisService.scanByPattern).toHaveBeenCalledWith(tokensPattern);
      expect(redisService.deleteMany).toHaveBeenCalledWith(tokenKeys);
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(jtiValues);
    });
  });

  describe('revokeAllUserApiTokens', () => {
    let mockQueryBuilder: any;

    beforeEach(() => {
      mockQueryBuilder = {
        delete: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        returning: jest.fn().mockReturnThis(),
        useTransaction: jest.fn().mockReturnThis(),
        execute: jest.fn(),
      };

      jest
        .spyOn(apiTokensRepository, 'createQueryBuilder')
        .mockReturnValue(mockQueryBuilder);
    });

    it('should revoke all API tokens and delete them from Redis cache if cache TTL is set', async () => {
      const userId = 'user123';
      const tokens = [{ jti: 'token1' }, { jti: 'token2' }];

      (
        apiTokensRepository.createQueryBuilder().delete().where as jest.Mock
      ).mockReturnValue({
        returning: jest.fn().mockReturnThis(),
        useTransaction: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({
          raw: tokens,
        }),
      });

      config.security.apiTokensJtiCacheTtl = 3600;

      const redisDeleteManySpy = jest
        .spyOn(service['redisService'], 'deleteMany')
        .mockResolvedValue(undefined);

      const revokeForApiGatewaySpy = jest
        .spyOn(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      const result = await service.revokeAllUserApiTokens(userId);

      const expectedRedisKeys = tokens.map((token) =>
        service['getApiTokenCacheStorageKey'](token.jti),
      );

      expect(redisDeleteManySpy).toHaveBeenCalledWith(expectedRedisKeys); // Ensure Redis deleteMany is called with correct keys
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(
        tokens.map((token) => token.jti),
      );
      expect(result).toBe(true);
    });

    it('should revoke all API tokens without Redis cache deletion when TTL is not set', async () => {
      const userId = 'user123';
      const tokens = [{ jti: 'token1' }, { jti: 'token2' }];

      (
        apiTokensRepository.createQueryBuilder().delete().where as jest.Mock
      ).mockReturnValue({
        returning: jest.fn().mockReturnThis(),
        useTransaction: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({
          raw: tokens,
        }),
      });

      config.security.apiTokensJtiCacheTtl = 0;

      const redisDeleteManySpy = jest
        .spyOn(service['redisService'], 'deleteMany')
        .mockResolvedValue(undefined);
      const revokeForApiGatewaySpy = jest
        .spyOn(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      const result = await service.revokeAllUserApiTokens(userId);

      expect(redisDeleteManySpy).not.toHaveBeenCalled();
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(
        tokens.map((token) => token.jti),
      );
      expect(result).toBe(true);
    });

    it('should return false if no tokens are found', async () => {
      const userId = 'user123';

      (
        apiTokensRepository.createQueryBuilder().delete().where as jest.Mock
      ).mockReturnValue({
        returning: jest.fn().mockReturnThis(),
        useTransaction: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({
          raw: [],
        }),
      });

      const redisDeleteManySpy = jest
        .spyOn(service['redisService'], 'deleteMany')
        .mockResolvedValue(undefined);
      const revokeForApiGatewaySpy = jest
        .spyOn(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      const result = await service.revokeAllUserApiTokens(userId);

      expect(redisDeleteManySpy).not.toHaveBeenCalled();
      expect(revokeForApiGatewaySpy).not.toHaveBeenCalled();
      expect(result).toBe(false);
    });

    it('should handle errors during API Gateway revocation', async () => {
      const userId = 'user123';
      const tokens = [{ jti: 'token1' }, { jti: 'token2' }];

      (
        apiTokensRepository.createQueryBuilder().delete().where as jest.Mock
      ).mockReturnValue({
        returning: jest.fn().mockReturnThis(),
        useTransaction: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({
          raw: tokens,
        }),
      });

      config.security.apiTokensJtiCacheTtl = 3600;

      const redisDeleteManySpy = jest
        .spyOn(service['redisService'], 'deleteMany')
        .mockResolvedValue(undefined);

      const revokeForApiGatewaySpy = jest
        .spyOn(service, 'revokeForApiGateway')
        .mockRejectedValue(new Error('API Gateway error'));

      await expect(service.revokeAllUserApiTokens(userId)).rejects.toThrow(
        'API Gateway error',
      );

      expect(redisDeleteManySpy).toHaveBeenCalledWith(
        tokens.map((token) => service['getApiTokenCacheStorageKey'](token.jti)),
      );
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(
        tokens.map((token) => token.jti),
      );
    });
  });

  describe('revokeUserTokenByJti', () => {
    const userId = 'user123';
    const jti = 'token-jti';
    const tokenStorageKey = `token:${jti}:${userId}`;

    it('should revoke the user token and delete it from Redis', async () => {
      redisService.delete = jest.fn().mockResolvedValue(undefined);
      const revokeForApiGatewaySpy = jest
        .spyOn<any, any>(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      await service.revokeUserTokenByJti(userId, jti);

      expect(redisService.delete).toHaveBeenCalledWith(tokenStorageKey);
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(jti);
    });

    it('should handle errors during Redis deletion gracefully', async () => {
      redisService.delete = jest
        .fn()
        .mockRejectedValue(new Error('Redis deletion error'));
      const revokeForApiGatewaySpy = jest.spyOn<any, any>(
        service,
        'revokeForApiGateway',
      );

      await expect(service.revokeUserTokenByJti(userId, jti)).rejects.toThrow(
        'Redis deletion error',
      );

      expect(redisService.delete).toHaveBeenCalledWith(tokenStorageKey);
      expect(revokeForApiGatewaySpy).not.toHaveBeenCalled();
    });

    it('should handle errors during API Gateway revocation gracefully', async () => {
      redisService.delete = jest.fn().mockResolvedValue(undefined);
      const revokeForApiGatewaySpy = jest
        .spyOn<any, any>(service, 'revokeForApiGateway')
        .mockRejectedValue(new Error('API Gateway revocation error'));

      await expect(service.revokeUserTokenByJti(userId, jti)).rejects.toThrow(
        'API Gateway revocation error',
      );

      expect(redisService.delete).toHaveBeenCalledWith(tokenStorageKey);
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(jti);
    });
  });

  describe('revokeApiToken', () => {
    const userId = 'user123';
    const jti = 'token456';

    it('should revoke the API token and call the API Gateway revocation', async () => {
      (apiTokensRepository.delete as jest.Mock).mockResolvedValue({
        affected: 1,
      });

      const revokeForApiGatewaySpy = jest
        .spyOn<any, any>(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      const result = await service.revokeApiToken(userId, jti);

      expect(apiTokensRepository.delete).toHaveBeenCalledWith({
        userId: Buffer.from(userId, 'hex'),
        jti,
      });

      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(jti);

      expect(result).toBe(true);
    });

    it('should return false if the API token is not found', async () => {
      (apiTokensRepository.delete as jest.Mock).mockResolvedValue({
        affected: 0,
      });

      const revokeForApiGatewaySpy = jest
        .spyOn<any, any>(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      const result = await service.revokeApiToken(userId, jti);

      expect(apiTokensRepository.delete).toHaveBeenCalledWith({
        userId: Buffer.from(userId, 'hex'),
        jti,
      });

      expect(revokeForApiGatewaySpy).not.toHaveBeenCalled();

      expect(result).toBe(false);
    });

    it('should handle errors during API Gateway revocation gracefully', async () => {
      (apiTokensRepository.delete as jest.Mock).mockResolvedValue({
        affected: 1,
      });

      const revokeForApiGatewaySpy = jest
        .spyOn<any, any>(service, 'revokeForApiGateway')
        .mockRejectedValue(new Error('API Gateway revocation error'));

      await expect(service.revokeApiToken(userId, jti)).rejects.toThrow(
        'API Gateway revocation error',
      );

      expect(apiTokensRepository.delete).toHaveBeenCalledWith({
        userId: Buffer.from(userId, 'hex'),
        jti,
      });

      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(jti);
    });

    it('should delete the token from Redis cache if cache TTL is set', async () => {
      (apiTokensRepository.delete as jest.Mock).mockResolvedValue({
        affected: 1,
      });

      config.security.apiTokensJtiCacheTtl = 3600;

      const redisDeleteSpy = jest
        .spyOn(service['redisService'], 'delete')
        .mockResolvedValue(undefined);
      const revokeForApiGatewaySpy = jest
        .spyOn(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      const result = await service.revokeApiToken(userId, jti);

      expect(redisDeleteSpy).toHaveBeenCalledWith(
        service['getApiTokenCacheStorageKey'](jti),
      );
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(jti);
      expect(result).toBe(true);
    });

    it('should not delete from Redis if cache TTL is not set', async () => {
      (apiTokensRepository.delete as jest.Mock).mockResolvedValue({
        affected: 1,
      });

      config.security.apiTokensJtiCacheTtl = 0;

      const redisDeleteSpy = jest
        .spyOn(service['redisService'], 'delete')
        .mockResolvedValue(undefined);
      const revokeForApiGatewaySpy = jest
        .spyOn(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      const result = await service.revokeApiToken(userId, jti);

      expect(redisDeleteSpy).not.toHaveBeenCalled();
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(jti);
      expect(result).toBe(true);
    });

    it('should not call Redis or API Gateway if token is not found', async () => {
      (apiTokensRepository.delete as jest.Mock).mockResolvedValue({
        affected: 0,
      });

      const redisDeleteSpy = jest
        .spyOn(service['redisService'], 'delete')
        .mockResolvedValue(undefined);
      const revokeForApiGatewaySpy = jest
        .spyOn(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      const result = await service.revokeApiToken(userId, jti);

      expect(redisDeleteSpy).not.toHaveBeenCalled();
      expect(revokeForApiGatewaySpy).not.toHaveBeenCalled();
      expect(result).toBe(false);
    });
  });

  describe('getTokenRedisStatus', () => {
    it('should return the token status from Redis when the token exists', async () => {
      const userId = 'test-user';
      const jti = 'mock-jti';
      const mockStatus = TokenStatuses.ACTIVE;

      (redisService.get as jest.Mock).mockResolvedValue(mockStatus);

      const result = await service.getTokenRedisStatus(userId, jti);

      expect(result).toEqual(mockStatus);
      expect(redisService.get).toHaveBeenCalledWith(`token:${jti}:${userId}`);
    });

    it('should return null when the token does not exist in Redis', async () => {
      const userId = 'test-user';
      const jti = 'mock-jti';

      (redisService.get as jest.Mock).mockResolvedValue(null);

      const result = await service.getTokenRedisStatus(userId, jti);

      expect(result).toBeNull();
      expect(redisService.get).toHaveBeenCalledWith(`token:${jti}:${userId}`);
    });
  });
});

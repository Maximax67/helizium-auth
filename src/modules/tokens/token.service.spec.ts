import { Test, TestingModule } from '@nestjs/testing';
import { TokenService } from './token.service';
import { RedisService } from '../redis/redis.service';
import { ApiToken } from './entities';
import { nanoid } from 'nanoid';
import * as jwt from 'jsonwebtoken';
import { getKidMapping } from '../../common/helpers';
import { TokenTypes, TokenLimits, TokenStatuses } from '../../common/enums';
import { config } from '../../config';

// TODO FIX, switch to typeorm
// eslint-disable-next-line @typescript-eslint/no-unused-vars
type Model<T> = any;
const Model: any = {};

jest.mock('axios');

jest.mock('nanoid');
jest.mock('jsonwebtoken');
jest.mock('../../common/helpers', () => ({
  getKidMapping: jest.fn(),
}));

describe('TokenService', () => {
  let service: TokenService;
  let redisService: RedisService;
  let apiTokenModel: Model<ApiToken>;

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
          provide: '1234', // TODO FIX
          useValue: {
            create: jest.fn(),
            findOne: jest.fn(),
            find: jest.fn(),
            findOneAndDelete: jest.fn(),
            deleteMany: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<TokenService>(TokenService);
    redisService = module.get<RedisService>(RedisService);
    apiTokenModel = module.get<Model<ApiToken>>('123'); // TODO FIX
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

    it('should define revokeUserTokenByJti()', () => {
      expect(service.revokeUserTokenByJti).toBeDefined();
      expect(typeof service.revokeUserTokenByJti).toBe('function');
    });

    it('should define revokeApiToken()', () => {
      expect(service.revokeApiToken).toBeDefined();
      expect(typeof service.revokeApiToken).toBe('function');
    });

    it('should define getTokenRedisStatus()', () => {
      expect(service.getTokenRedisStatus).toBeDefined();
      expect(typeof service.getTokenRedisStatus).toBe('function');
    });
  });

  describe('generateApiToken', () => {
    const mockUserId = 'user123';
    const mockTitle = 'Test API Token';
    const mockWriteAccess = true;
    const mockJti = 'mocked-jti';
    const mockKid = 'mocked-kid';
    const mockToken = 'signed-token';

    beforeEach(() => {
      (nanoid as jest.Mock).mockReturnValue(mockJti);

      (getKidMapping as jest.Mock).mockResolvedValue({
        API: mockKid,
      });

      (jwt.sign as jest.Mock).mockReturnValue(mockToken);
    });

    it('should generate an API token and store it in MongoDB', async () => {
      const result = await service.generateApiToken(
        mockUserId,
        mockTitle,
        mockWriteAccess,
      );

      expect(nanoid).toHaveBeenCalled();
      expect(getKidMapping).toHaveBeenCalled();

      expect(jwt.sign).toHaveBeenCalledWith(
        {
          userId: mockUserId,
          jti: mockJti,
          limits: TokenLimits.DEFAULT,
          type: TokenTypes.API,
        },
        expect.any(String),
        {
          algorithm: 'RS256',
          keyid: mockKid,
        },
      );

      expect(apiTokenModel.create).toHaveBeenCalledWith({
        userId: mockUserId,
        jti: mockJti,
        title: mockTitle,
        writeAccess: mockWriteAccess,
      });

      expect(result).toBe(mockToken);
    });

    it('should generate an API token with read-only access if writeAccess is false', async () => {
      const readOnlyAccess = false;

      const result = await service.generateApiToken(
        mockUserId,
        mockTitle,
        readOnlyAccess,
      );

      expect(jwt.sign).toHaveBeenCalledWith(
        {
          userId: mockUserId,
          jti: mockJti,
          limits: TokenLimits.READ_ONLY,
          type: TokenTypes.API,
        },
        expect.any(String),
        {
          algorithm: 'RS256',
          keyid: mockKid,
        },
      );

      expect(apiTokenModel.create).toHaveBeenCalledWith({
        userId: mockUserId,
        jti: mockJti,
        title: mockTitle,
        writeAccess: readOnlyAccess,
      });

      expect(result).toBe(mockToken);
    });

    it('should handle errors gracefully when creating API token', async () => {
      (apiTokenModel.create as jest.Mock).mockRejectedValue(
        new Error('MongoDB Error'),
      );

      await expect(
        service.generateApiToken(mockUserId, mockTitle, mockWriteAccess),
      ).rejects.toThrow('MongoDB Error');
    });
  });

  describe('generateApiToken', () => {
    const mockUserId = 'user123';
    const mockTitle = 'Test API Token';
    const mockWriteAccess = true;
    const mockJti = 'mocked-jti';
    const mockKid = 'mocked-kid';
    const mockToken = 'signed-token';

    beforeEach(() => {
      (nanoid as jest.Mock).mockReturnValue(mockJti);

      (getKidMapping as jest.Mock).mockResolvedValue({
        API: mockKid,
      });

      (jwt.sign as jest.Mock).mockReturnValue(mockToken);
    });

    it('should generate an API token and store it in MongoDB', async () => {
      const result = await service.generateApiToken(
        mockUserId,
        mockTitle,
        mockWriteAccess,
      );

      expect(nanoid).toHaveBeenCalled();
      expect(getKidMapping).toHaveBeenCalled();

      expect(jwt.sign).toHaveBeenCalledWith(
        {
          userId: mockUserId,
          jti: mockJti,
          limits: TokenLimits.DEFAULT,
          type: TokenTypes.API,
        },
        expect.any(String),
        {
          algorithm: 'RS256',
          keyid: mockKid,
        },
      );

      expect(apiTokenModel.create).toHaveBeenCalledWith({
        userId: mockUserId,
        jti: mockJti,
        title: mockTitle,
        writeAccess: mockWriteAccess,
      });

      expect(result).toBe(mockToken);
    });

    it('should generate an API token with read-only access if writeAccess is false', async () => {
      const readOnlyAccess = false;

      const result = await service.generateApiToken(
        mockUserId,
        mockTitle,
        readOnlyAccess,
      );

      expect(jwt.sign).toHaveBeenCalledWith(
        {
          userId: mockUserId,
          jti: mockJti,
          limits: TokenLimits.READ_ONLY,
          type: TokenTypes.API,
        },
        expect.any(String),
        {
          algorithm: 'RS256',
          keyid: mockKid,
        },
      );

      expect(apiTokenModel.create).toHaveBeenCalledWith({
        userId: mockUserId,
        jti: mockJti,
        title: mockTitle,
        writeAccess: readOnlyAccess,
      });

      expect(result).toBe(mockToken);
    });

    it('should handle errors gracefully when creating API token', async () => {
      (apiTokenModel.create as jest.Mock).mockRejectedValue(
        new Error('MongoDB Error'),
      );

      await expect(
        service.generateApiToken(mockUserId, mockTitle, mockWriteAccess),
      ).rejects.toThrow('MongoDB Error');
    });
  });

  describe('validateToken', () => {
    const mockAccessToken = 'mocked-access-token';
    const mockApiToken = 'mocked-api-token';
    const mockUserId = 'user123';
    const mockJti = 'mocked-jti';

    const mockAccessPayload = {
      userId: mockUserId,
      jti: mockJti,
      type: TokenTypes.ACCESS,
      limits: TokenLimits.DEFAULT,
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 60,
    };

    const mockApiPayload = {
      userId: mockUserId,
      jti: mockJti,
      type: TokenTypes.API,
      limits: TokenLimits.READ_ONLY,
      iat: Math.floor(Date.now() / 1000) - 60,
    };

    beforeEach(() => {
      jest.clearAllMocks();
    });

    it('should validate a valid access token and return decoded info with active status', async () => {
      (jwt.verify as jest.Mock).mockReturnValue(mockAccessPayload);

      jest
        .spyOn(service, 'getTokenRedisStatus')
        .mockResolvedValue(TokenStatuses.ACTIVE);

      const result = await service.validateToken(mockAccessToken, false);

      expect(jwt.verify).toHaveBeenCalledWith(
        mockAccessToken,
        config.keys.jwtAccessPublicKey,
      );

      expect(service.getTokenRedisStatus).toHaveBeenCalledWith(
        mockUserId,
        mockJti,
      );

      expect(result).toEqual({
        decoded: mockAccessPayload,
        status: TokenStatuses.ACTIVE,
      });
    });

    it('should validate a valid API token and return decoded info with active status', async () => {
      (jwt.verify as jest.Mock).mockReturnValue(mockApiPayload);

      jest
        .spyOn(apiTokenModel, 'findOne')
        .mockResolvedValue({ writeAccess: false });

      const result = await service.validateToken(mockApiToken, true);

      expect(jwt.verify).toHaveBeenCalledWith(
        mockApiToken,
        config.keys.jwtApiPublicKey,
      );

      expect(apiTokenModel.findOne).toHaveBeenCalledWith(
        { userId: mockUserId, jti: mockJti },
        { writeAccess: 1 },
      );

      expect(result).toEqual({
        decoded: mockApiPayload,
        status: TokenStatuses.ACTIVE,
      });
    });

    it('should return null if token is invalid', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      const result = await service.validateToken(mockAccessToken, false);

      expect(jwt.verify).toHaveBeenCalledWith(
        mockAccessToken,
        config.keys.jwtAccessPublicKey,
      );

      expect(result).toBeNull();
    });

    it('should return null if Redis status is missing or invalid for access token', async () => {
      (jwt.verify as jest.Mock).mockReturnValue(mockAccessPayload);

      jest.spyOn(service, 'getTokenRedisStatus').mockResolvedValue(null);

      const result = await service.validateToken(mockAccessToken, false);

      expect(service.getTokenRedisStatus).toHaveBeenCalledWith(
        mockUserId,
        mockJti,
      );

      expect(result).toBeNull();
    });

    it('should return null if API token write access does not match limits', async () => {
      (jwt.verify as jest.Mock).mockReturnValue(mockApiPayload);

      jest
        .spyOn(apiTokenModel, 'findOne')
        .mockResolvedValue({ writeAccess: true });

      const result = await service.validateToken(mockApiToken, true);

      expect(apiTokenModel.findOne).toHaveBeenCalledWith(
        { userId: mockUserId, jti: mockJti },
        { writeAccess: 1 },
      );

      expect(result).toBeNull();
    });

    it('should handle expired access tokens by returning null', async () => {
      const expiredAccessPayload = {
        ...mockAccessPayload,
        exp: Math.floor(Date.now() / 1000) - 60,
      };

      (jwt.verify as jest.Mock).mockReturnValue(expiredAccessPayload);

      const result = await service.validateToken(mockAccessToken, false);

      expect(jwt.verify).toHaveBeenCalledWith(
        mockAccessToken,
        config.keys.jwtAccessPublicKey,
      );

      expect(result).toBeNull();
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
    const mockApiTokens = [
      { _id: 'token1', userId: mockUserId, title: 'Token 1' },
      { _id: 'token2', userId: mockUserId, title: 'Token 2' },
    ];

    it('should return a list of API tokens for a user', async () => {
      jest.spyOn(apiTokenModel, 'find').mockReturnValue({
        lean: jest.fn().mockResolvedValue(mockApiTokens),
      } as any);

      const result = await service.getUserApiTokens(mockUserId);

      expect(apiTokenModel.find).toHaveBeenCalledWith({ userId: mockUserId });

      expect(result).toEqual([
        { ...mockApiTokens[0], id: 'token1' },
        { ...mockApiTokens[1], id: 'token2' },
      ]);
    });

    it('should return an empty array if no tokens are found', async () => {
      jest.spyOn(apiTokenModel, 'find').mockReturnValue({
        lean: jest.fn().mockResolvedValue([]),
      } as any);

      const result = await service.getUserApiTokens(mockUserId);

      expect(result).toEqual([]);
    });
  });

  describe('getUserApiToken', () => {
    const mockUserId = 'user123';
    const mockTokenId = 'token1';
    const mockApiToken = {
      _id: mockTokenId,
      userId: mockUserId,
      title: 'Token 1',
    };

    it('should return a specific API token if it exists', async () => {
      jest.spyOn(apiTokenModel, 'findOne').mockReturnValue({
        lean: jest.fn().mockResolvedValue(mockApiToken),
      } as any);

      const result = await service.getUserApiToken(mockUserId, mockTokenId);

      expect(apiTokenModel.findOne).toHaveBeenCalledWith({
        _id: mockTokenId,
        userId: mockUserId,
      });

      expect(result).toEqual({ ...mockApiToken, id: 'token1' });
    });

    it('should throw an error if the API token is not found', async () => {
      jest.spyOn(apiTokenModel, 'findOne').mockReturnValue({
        lean: jest.fn().mockResolvedValue(null),
      } as any);

      await expect(
        service.getUserApiToken(mockUserId, mockTokenId),
      ).rejects.toThrow('Not found api token');
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
    const tokenId = 'token456';
    const deletedToken = { jti: 'token-jti' };

    it('should revoke the API token and call the API Gateway revocation', async () => {
      apiTokenModel.findOneAndDelete = jest
        .fn()
        .mockResolvedValue(deletedToken);
      const revokeForApiGatewaySpy = jest
        .spyOn<any, any>(service, 'revokeForApiGateway')
        .mockResolvedValue(undefined);

      const result = await service.revokeApiToken(userId, tokenId);

      expect(apiTokenModel.findOneAndDelete).toHaveBeenCalledWith({
        _id: tokenId,
        userId,
      });
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(deletedToken.jti);
      expect(result).toBe(true);
    });

    it('should return false if the API token is not found', async () => {
      apiTokenModel.findOneAndDelete = jest.fn().mockResolvedValue(null); // No token found

      const result = await service.revokeApiToken(userId, tokenId);

      expect(apiTokenModel.findOneAndDelete).toHaveBeenCalledWith({
        _id: tokenId,
        userId,
      });
      expect(result).toBe(false);
    });

    it('should handle errors during API Gateway revocation gracefully', async () => {
      apiTokenModel.findOneAndDelete = jest
        .fn()
        .mockResolvedValue(deletedToken);
      const revokeForApiGatewaySpy = jest
        .spyOn<any, any>(service, 'revokeForApiGateway')
        .mockRejectedValue(new Error('API Gateway revocation error'));

      await expect(service.revokeApiToken(userId, tokenId)).rejects.toThrow(
        'API Gateway revocation error',
      );

      expect(apiTokenModel.findOneAndDelete).toHaveBeenCalledWith({
        _id: tokenId,
        userId,
      });
      expect(revokeForApiGatewaySpy).toHaveBeenCalledWith(deletedToken.jti);
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

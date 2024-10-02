import { Test, TestingModule } from '@nestjs/testing';
import { TotpAuthService } from './totp-auth.service';
import { TotpService } from '../totp';
import { RedisService } from '../redis';
import { UserService } from '../users';

describe('TotpAuthService', () => {
  let totpAuthService: TotpAuthService;
  let totpService: TotpService;
  let redisService: RedisService;
  let userService: UserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TotpAuthService,
        {
          provide: TotpService,
          useValue: {
            initTotp: jest.fn().mockReturnValue({
              secret: { base32: 'mockBase32Secret' },
              toString: jest.fn().mockReturnValue('mockTotpString'),
            }),
            validateTotp: jest.fn(),
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
          provide: UserService,
          useValue: {
            setTotpSecret: jest.fn(),
            getTotpSecret: jest.fn(),
            disableTotpMfa: jest.fn(),
          },
        },
      ],
    }).compile();

    totpAuthService = module.get<TotpAuthService>(TotpAuthService);
    totpService = module.get<TotpService>(TotpService);
    redisService = module.get<RedisService>(RedisService);
    userService = module.get<UserService>(UserService);
  });

  it('should be defined', () => {
    expect(totpAuthService).toBeDefined();
  });

  describe('TotpAuthService', () => {
    it('should define initTotp()', () => {
      expect(totpAuthService.initTotp).toBeDefined();
      expect(typeof totpAuthService.initTotp).toBe('function');
    });

    it('should define validateTotp()', () => {
      expect(totpAuthService.validateTotp).toBeDefined();
      expect(typeof totpAuthService.validateTotp).toBe('function');
    });

    it('should define disableTotp()', () => {
      expect(totpAuthService.disableTotp).toBeDefined();
      expect(typeof totpAuthService.disableTotp).toBe('function');
    });
  });

  describe('initTotp', () => {
    it('should initialize TOTP and store the secret in Redis', async () => {
      const userId = 'user123';
      const storageKey = `totp:${userId}`;

      const result = await totpAuthService.initTotp(userId);

      expect(result).toBe('mockTotpString');
      expect(redisService.set).toHaveBeenCalledWith(
        storageKey,
        'mockBase32Secret',
        900,
      );
    });
  });

  describe('validateTotp', () => {
    it('should validate TOTP and return true if valid', async () => {
      const userId = 'user123';
      const token = '123456';
      const storageKey = `totp:${userId}`;

      redisService.get = jest.fn().mockResolvedValue('mockBase32Secret');
      totpService.validateTotp = jest.fn().mockReturnValue(true);

      const result = await totpAuthService.validateTotp(userId, token, false);

      expect(redisService.get).toHaveBeenCalledWith(storageKey);
      expect(totpService.validateTotp).toHaveBeenCalledWith(
        'mockBase32Secret',
        token,
      );
      expect(redisService.delete).toHaveBeenCalledWith(storageKey);
      expect(userService.setTotpSecret).toHaveBeenCalledWith(
        userId,
        'mockBase32Secret',
      );
      expect(result).toBe(true);
    });

    it('should return false if TOTP is invalid', async () => {
      const userId = 'user123';
      const token = '654321';
      const storageKey = `totp:${userId}`;

      redisService.get = jest.fn().mockResolvedValue('mockBase32Secret');
      totpService.validateTotp = jest.fn().mockReturnValue(false);

      const result = await totpAuthService.validateTotp(userId, token, false);

      expect(redisService.get).toHaveBeenCalledWith(storageKey);
      expect(totpService.validateTotp).toHaveBeenCalledWith(
        'mockBase32Secret',
        token,
      );
      expect(result).toBe(false);
    });

    it('should throw an error if TOTP is missing and isRoot is true', async () => {
      const userId = 'user123';
      const token = '654321';

      await expect(
        totpAuthService.validateTotp(userId, token, true),
      ).rejects.toThrow('mfa passed');
    });

    it('should validate user TOTP secret if no temporary secret is found', async () => {
      const userId = 'user123';
      const token = '123456';

      redisService.get = jest.fn().mockResolvedValue(null);
      userService.getTotpSecret = jest.fn().mockResolvedValue('userSecret');
      totpService.validateTotp = jest.fn().mockReturnValue(true);

      const result = await totpAuthService.validateTotp(userId, token, false);

      expect(userService.getTotpSecret).toHaveBeenCalledWith(userId);
      expect(totpService.validateTotp).toHaveBeenCalledWith(
        'userSecret',
        token,
      );
      expect(result).toBe(true);
    });
  });

  describe('disableTotp', () => {
    it('should disable TOTP for the user', async () => {
      const userId = 'user123';

      await totpAuthService.disableTotp(userId);

      expect(userService.disableTotpMfa).toHaveBeenCalledWith(userId);
    });
  });
});

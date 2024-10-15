import { Test, TestingModule } from '@nestjs/testing';
import { MailService } from '../mail';
import { RedisService } from '../redis';
import * as otpGenerator from 'otp-generator';
import { EmailTemplatesEnum } from '../../common/enums';
import { APP_NAME } from '../../common/constants';
import { compile } from 'path-to-regexp';
import { EmailOtpService } from './email-otp.service';
import { config } from '../../config';

jest.mock('otp-generator', () => ({
  generate: jest.fn(),
}));

describe('EmailOtpService', () => {
  let emailOtpService: EmailOtpService;
  let mailService: MailService;
  let redisService: RedisService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EmailOtpService,
        {
          provide: MailService,
          useValue: {
            sendMail: jest.fn(),
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
      ],
    }).compile();

    emailOtpService = module.get<EmailOtpService>(EmailOtpService);
    mailService = module.get<MailService>(MailService);
    redisService = module.get<RedisService>(RedisService);
  });

  describe('sendOtp', () => {
    it('should generate OTP, store it in Redis, and send an email', async () => {
      const userId = 'user123';
      const token = 'token123';
      const email = 'test@example.com';
      const username = 'testUser';
      const otpMock = '123456';
      const ttl = 300;
      const isConfirmEmail = true;
      (otpGenerator.generate as jest.Mock).mockReturnValue(otpMock);

      const storageKey = `eotp:${userId}:${otpMock}`;
      const confirmLink = compile(config.email.confirmEmailFrontendUrl)({
        userId,
        otp: otpMock,
      });

      await emailOtpService.sendOtp(
        userId,
        token,
        email,
        username,
        isConfirmEmail,
        ttl,
      );

      expect(redisService.set).toHaveBeenCalledWith(storageKey, token, ttl);
      expect(mailService.sendMail).toHaveBeenCalledWith(
        email,
        EmailTemplatesEnum.CONFIRM_EMAIL,
        {
          appName: APP_NAME,
          username,
          otp: otpMock,
          url: confirmLink,
        },
      );
    });

    it('should use the correct TTL and template when not confirming email', async () => {
      const userId = 'user123';
      const token = 'token123';
      const email = 'test@example.com';
      const username = 'testUser';
      const otpMock = '654321';
      const ttl = 600;
      const isConfirmEmail = false;
      (otpGenerator.generate as jest.Mock).mockReturnValue(otpMock);

      const storageKey = `eotp:${userId}:${otpMock}`;

      await emailOtpService.sendOtp(
        userId,
        token,
        email,
        username,
        isConfirmEmail,
        ttl,
      );

      expect(redisService.set).toHaveBeenCalledWith(storageKey, token, ttl);
      expect(mailService.sendMail).toHaveBeenCalledWith(
        email,
        EmailTemplatesEnum.MFA_EMAIL,
        expect.objectContaining({
          appName: APP_NAME,
          username,
          otp: otpMock,
        }),
      );
    });
  });

  describe('verifyOtp', () => {
    it('should return the token if OTP is valid', async () => {
      const userId = 'user123';
      const otp = '123456';
      const token = 'token123';
      const storageKey = `eotp:${userId}:${otp}`;

      (redisService.get as jest.Mock).mockResolvedValue(token);

      const result = await emailOtpService.verifyOtp(userId, otp);

      expect(redisService.get).toHaveBeenCalledWith(storageKey);
      expect(redisService.delete).toHaveBeenCalledWith(storageKey);
      expect(result).toBe(token);
    });

    it('should return null if OTP is invalid', async () => {
      const userId = 'user123';
      const otp = '654321';
      const storageKey = `eotp:${userId}:${otp}`;

      (redisService.get as jest.Mock).mockResolvedValue(null);

      const result = await emailOtpService.verifyOtp(userId, otp);

      expect(redisService.get).toHaveBeenCalledWith(storageKey);
      expect(result).toBeNull();
      expect(redisService.delete).not.toHaveBeenCalled();
    });

    it('should return null if OTP is missing or has incorrect length', async () => {
      const result = await emailOtpService.verifyOtp('user123', '12');

      expect(result).toBeNull();
    });
  });

  describe('invalidateOtp', () => {
    it('should delete the OTP from Redis', async () => {
      const userId = 'user123';
      const otp = '123456';
      const storageKey = `eotp:${userId}:${otp}`;

      await emailOtpService.invalidateOtp(userId, otp);

      expect(redisService.delete).toHaveBeenCalledWith(storageKey);
    });
  });
});

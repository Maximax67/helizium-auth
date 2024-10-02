import { Test, TestingModule } from '@nestjs/testing';
import { TotpService } from './totp.service';
import * as OTPAuth from 'otpauth';
import { APP_NAME } from '../../../src/common/constants';

describe('TotpService', () => {
  let service: TotpService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TotpService],
    }).compile();

    service = module.get<TotpService>(TotpService);
  });

  describe('TotpService', () => {
    it('should define initTotp()', () => {
      expect(service.initTotp).toBeDefined();
      expect(typeof service.initTotp).toBe('function');
    });

    it('should define validateTotp()', () => {
      expect(service.validateTotp).toBeDefined();
      expect(typeof service.validateTotp).toBe('function');
    });
  });

  describe('initTotp', () => {
    it('should generate a new TOTP instance with a secret', () => {
      const secret = service['generateSecret']();
      jest.spyOn(service as any, 'generateSecret').mockReturnValue(secret);

      const totp = service.initTotp();

      expect(totp).toBeInstanceOf(OTPAuth.TOTP);
      expect(totp.secret).toEqual(secret);
      expect(totp.issuer).toEqual(APP_NAME);
      expect(totp.label).toEqual(APP_NAME);
    });
  });

  describe('validateTotp', () => {
    it('should the token should be a number, and have length of 6', () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const totp = service['getNewTotp'](secret);
      const token = totp.generate();

      expect(token).toMatch(/^\d{6}$/);
    });

    it('should return false for an invalid token', () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const invalidToken = '123456';

      const isValid = service.validateTotp(secret, invalidToken);

      expect(isValid).toBe(false);
    });
  });
});

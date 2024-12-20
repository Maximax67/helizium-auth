import { Test, TestingModule } from '@nestjs/testing';
import { HashService } from './hash.service';
import * as bcrypt from 'bcrypt';

jest.mock('bcrypt');

describe('HashService', () => {
  let service: HashService;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [HashService],
    }).compile();

    service = module.get<HashService>(HashService);
  });

  describe('hashService', () => {
    it('should define hashData()', () => {
      expect(service.hashData).toBeDefined();
      expect(typeof service.hashData).toBe('function');
    });

    it('should define compareHash()', () => {
      expect(service.compareHash).toBeDefined();
      expect(typeof service.compareHash).toBe('function');
    });
  });

  describe('hashData', () => {
    it('should hash the data using bcrypt', async () => {
      const data = 'testPassword';
      const hashedData = 'hashedPassword';

      (bcrypt.hash as jest.Mock).mockResolvedValue(hashedData);

      const result = await service.hashData(data);

      expect(result).toBe(hashedData);
      expect(bcrypt.hash).toHaveBeenCalledWith(data, 10);
    });
  });

  describe('compareHash', () => {
    it('should return true if the hash matches', async () => {
      const data = 'testPassword';
      const hash = 'hashedPassword';

      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await service.compareHash(data, hash);

      expect(result).toBe(true);
      expect(bcrypt.compare).toHaveBeenCalledWith(data, hash);
    });

    it('should return false if the hash does not match', async () => {
      const data = 'testPassword';
      const hash = 'hashedPassword';

      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const result = await service.compareHash(data, hash);

      expect(result).toBe(false);
      expect(bcrypt.compare).toHaveBeenCalledWith(data, hash);
    });
  });
});

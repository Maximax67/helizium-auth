import { Test, TestingModule } from '@nestjs/testing';
import { RedisService } from './redis.service';
import Redis from 'ioredis-mock';

const mockTracer = {
  startSpan: jest.fn().mockReturnValue({
    end: jest.fn(),
    setStatus: jest.fn(),
  }),
};

describe('RedisService', () => {
  let redisService: RedisService;
  let redisMock: typeof Redis.prototype;

  beforeAll(async () => {
    redisMock = new Redis();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RedisService,
        { provide: 'REDIS_CLIENT', useValue: redisMock },
        { provide: 'TRACER', useValue: mockTracer },
      ],
    }).compile();

    redisService = module.get<RedisService>(RedisService);
  });

  afterEach((done) => {
    redisMock.flushall().then(() => done());
  });

  describe('RedisService', () => {
    it('should define set()', () => {
      expect(redisService.set).toBeDefined();
      expect(typeof redisService.set).toBe('function');
    });

    it('should define get()', () => {
      expect(redisService.get).toBeDefined();
      expect(typeof redisService.get).toBe('function');
    });

    it('should define delete()', () => {
      expect(redisService.delete).toBeDefined();
      expect(typeof redisService.delete).toBe('function');
    });

    it('should define setMany()', () => {
      expect(redisService.setMany).toBeDefined();
      expect(typeof redisService.setMany).toBe('function');
    });

    it('should define scanByPattern()', () => {
      expect(redisService.scanByPattern).toBeDefined();
      expect(typeof redisService.scanByPattern).toBe('function');
    });

    it('should define deleteMany()', () => {
      expect(redisService.deleteMany).toBeDefined();
      expect(typeof redisService.deleteMany).toBe('function');
    });

    it('should define deleteByPattern()', () => {
      expect(redisService.deleteByPattern).toBeDefined();
      expect(typeof redisService.deleteByPattern).toBe('function');
    });
  });

  describe('set', () => {
    it('should set a value with expiry in redis', async () => {
      const key = 'test-key';
      const value = 'test-value';
      const expiry = 3600;

      await redisService.set(key, value, expiry);

      const result = await redisMock.get(key);
      expect(result).toEqual(value);
      expect(redisMock.ttl(key)).resolves.toBeLessThanOrEqual(expiry);
    });
  });

  describe('get', () => {
    it('should return a value from redis', async () => {
      const key = 'test-key';
      const value = 'test-value';
      await redisMock.set(key, value);

      const result = await redisService.get(key);
      expect(result).toEqual(value);
    });

    it('should return undefined if the key does not exist', async () => {
      const result = await redisService.get('non-existent-key');
      expect(result).toBeUndefined();
    });
  });

  describe('delete', () => {
    it('should delete a key from redis', async () => {
      const key = 'test-key';
      await redisMock.set(key, 'some-value');
      await redisService.delete(key);

      const result = await redisMock.get(key);
      expect(result).toBeNull();
    });
  });

  describe('setMany', () => {
    it('should set multiple key-value pairs in redis', async () => {
      const keyValuePairs = [
        { key: 'key1', value: 'value1' },
        { key: 'key2', value: 'value2' },
      ];

      await redisService.setMany(keyValuePairs);

      const result1 = await redisMock.get('key1');
      const result2 = await redisMock.get('key2');

      expect(result1).toEqual('value1');
      expect(result2).toEqual('value2');
    });
  });

  describe('scanByPattern', () => {
    it('should return keys that match the pattern', async () => {
      await redisMock.set('test-1', 'value1');
      await redisMock.set('test-2', 'value2');
      await redisMock.set('other-1', 'value3');

      const keys = await redisService.scanByPattern('test-*');
      expect(keys).toEqual(expect.arrayContaining(['test-1', 'test-2']));
    });
  });

  describe('deleteMany', () => {
    it('should delete multiple keys from redis', async () => {
      await redisMock.set('key1', 'value1');
      await redisMock.set('key2', 'value2');

      await redisService.deleteMany(['key1', 'key2']);

      const result1 = await redisMock.get('key1');
      const result2 = await redisMock.get('key2');

      expect(result1).toBeNull();
      expect(result2).toBeNull();
    });
  });

  describe('deleteByPattern', () => {
    it('should delete keys by pattern', async () => {
      await redisMock.set('test-1', 'value1');
      await redisMock.set('test-2', 'value2');
      await redisMock.set('other-1', 'value3');

      await redisService.deleteByPattern('test-*');

      const result1 = await redisMock.get('test-1');
      const result2 = await redisMock.get('test-2');
      const result3 = await redisMock.get('other-1');

      expect(result1).toBeNull();
      expect(result2).toBeNull();
      expect(result3).toEqual('value3');
    });
  });
});

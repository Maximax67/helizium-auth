import Redis from 'ioredis';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class RedisService {
  private readonly redis: Redis;

  constructor(@Inject('REDIS_CLIENT') redisClient: Redis) {
    this.redis = redisClient;
  }

  async set(
    key: string,
    value: string = '1',
    expiry: number = 3600,
  ): Promise<void> {
    await this.redis.set(key, value, 'EX', expiry);
  }

  async setMany(
    keyValuePairs: { key: string; value: string; expiry?: number }[],
    batchSize: number = 100,
  ): Promise<void> {
    for (let i = 0; i < keyValuePairs.length; i += batchSize) {
      const batch = keyValuePairs.slice(i, i + batchSize);
      const pipeline = this.redis.pipeline();

      batch.forEach(({ key, value, expiry = 3600 }) => {
        pipeline.set(key, value, 'EX', expiry);
      });

      await pipeline.exec();
    }
  }

  async get(key: string): Promise<string | undefined> {
    return (await this.redis.get(key)) ?? undefined;
  }

  async delete(key: string): Promise<void> {
    await this.redis.del(key);
  }

  async scanByPattern(pattern: string, count: number = 100): Promise<string[]> {
    let cursor = '0';
    let keys: string[] = [];
    do {
      const [nextCursor, foundKeys] = await this.redis.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        count,
      );
      cursor = nextCursor;
      keys = keys.concat(foundKeys);
    } while (cursor !== '0');

    return keys;
  }

  async deleteMany(keys: string[], batchSize: number = 100): Promise<void> {
    for (let i = 0; i < keys.length; i += batchSize) {
      const batch = keys.slice(i, i + batchSize);
      const pipeline = this.redis.pipeline();
      batch.forEach((key) => pipeline.del(key));
      await pipeline.exec();
    }
  }

  async deleteByPattern(
    pattern: string,
    count: number = 100,
    deleteBatchSize: number = 100,
  ): Promise<void> {
    const keys = await this.scanByPattern(pattern, count);
    await this.deleteMany(keys, deleteBatchSize);
  }
}

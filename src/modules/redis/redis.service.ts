import Redis from 'ioredis';
import { Inject, Injectable } from '@nestjs/common';
import { SpanStatusCode, Tracer } from '@opentelemetry/api';
import { config } from '../../config';
import { getErrorMessage } from '../../common/helpers';

@Injectable()
export class RedisService {
  private readonly spanAttributes = {
    'db.system': 'redis',
    'db.connection_string': config.redisUrl,
  };

  constructor(
    @Inject('REDIS_CLIENT') private readonly redis: Redis,
    @Inject('TRACER') private readonly tracer: Tracer,
  ) {}

  async set(
    key: string,
    value: string = '1',
    expiry: number = 3600,
  ): Promise<void> {
    const span = this.tracer.startSpan('redis:set', {
      attributes: this.spanAttributes,
    });
    try {
      await this.redis.set(key, value, 'EX', expiry);
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: getErrorMessage(error),
      });
      throw error; // Re-throw the error after logging
    } finally {
      span.end();
    }
  }

  async setMany(
    keyValuePairs: { key: string; value: string; expiry?: number }[],
    batchSize: number = 100,
  ): Promise<void> {
    const span = this.tracer.startSpan('redis:setMany', {
      attributes: this.spanAttributes,
    });
    try {
      for (let i = 0; i < keyValuePairs.length; i += batchSize) {
        const batch = keyValuePairs.slice(i, i + batchSize);
        const pipeline = this.redis.pipeline();

        batch.forEach(({ key, value, expiry = 3600 }) => {
          pipeline.set(key, value, 'EX', expiry);
        });

        await pipeline.exec();
      }
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: getErrorMessage(error),
      });
      throw error;
    } finally {
      span.end();
    }
  }

  async get(key: string): Promise<string | undefined> {
    const span = this.tracer.startSpan('redis:get', {
      attributes: this.spanAttributes,
    });
    try {
      return (await this.redis.get(key)) ?? undefined;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: getErrorMessage(error),
      });
      throw error;
    } finally {
      span.end();
    }
  }

  async delete(key: string): Promise<void> {
    const span = this.tracer.startSpan('redis:delete', {
      attributes: this.spanAttributes,
    });
    try {
      await this.redis.del(key);
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: getErrorMessage(error),
      });
      throw error;
    } finally {
      span.end();
    }
  }

  async scanByPattern(pattern: string, count: number = 100): Promise<string[]> {
    const span = this.tracer.startSpan('redis:scanByPattern', {
      attributes: this.spanAttributes,
    });
    try {
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
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: getErrorMessage(error),
      });
      throw error;
    } finally {
      span.end();
    }
  }

  async deleteMany(keys: string[], batchSize: number = 100): Promise<void> {
    const span = this.tracer.startSpan('redis:deleteMany', {
      attributes: this.spanAttributes,
    });
    try {
      for (let i = 0; i < keys.length; i += batchSize) {
        const batch = keys.slice(i, i + batchSize);
        const pipeline = this.redis.pipeline();
        batch.forEach((key) => pipeline.del(key));
        await pipeline.exec();
      }
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: getErrorMessage(error),
      });
      throw error;
    } finally {
      span.end();
    }
  }

  async deleteByPattern(
    pattern: string,
    count: number = 100,
    deleteBatchSize: number = 100,
  ): Promise<void> {
    const span = this.tracer.startSpan('redis:deleteByPattern', {
      attributes: this.spanAttributes,
    });
    try {
      const keys = await this.scanByPattern(pattern, count);
      await this.deleteMany(keys, deleteBatchSize);
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: getErrorMessage(error),
      });
      throw error;
    } finally {
      span.end();
    }
  }
}

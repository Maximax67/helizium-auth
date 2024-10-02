import Redis from 'ioredis';
import { Module } from '@nestjs/common';
import { RedisService } from './redis.service';
import { config } from '../../config';

@Module({
  providers: [
    RedisService,
    {
      provide: 'REDIS_CLIENT',
      useFactory: () => {
        return new Redis(config.redisUrl);
      },
    },
  ],
  exports: [RedisService],
})
export class RedisModule {}

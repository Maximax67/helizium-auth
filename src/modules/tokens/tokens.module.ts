import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { ApiToken } from './entities';
import { RedisModule } from '../redis';
import { CookiesModule } from '../cookies';
import { TokenService } from './token.service';
import { TokensController } from './tokens.controller';

@Module({
  imports: [RedisModule, TypeOrmModule.forFeature([ApiToken]), CookiesModule],
  providers: [TokenService],
  controllers: [TokensController],
  exports: [TokenService],
})
export class TokensModule {}

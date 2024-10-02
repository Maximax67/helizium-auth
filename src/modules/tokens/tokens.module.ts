import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';

import { RedisModule } from '../redis';
import { CookiesModule } from '../cookies';
import { TokenService } from './token.service';
import { TokensController } from './tokens.controller';
import { ApiToken, ApiTokenSchema } from './schemas';

@Module({
  imports: [
    RedisModule,
    CookiesModule,
    MongooseModule.forFeature([
      { name: ApiToken.name, schema: ApiTokenSchema },
    ]),
  ],
  providers: [TokenService],
  controllers: [TokensController],
  exports: [TokenService],
})
export class TokensModule {}

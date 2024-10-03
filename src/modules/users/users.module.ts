import * as path from 'path';
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ClientsModule, Transport } from '@nestjs/microservices';

import { User } from './entities';
import { UserService } from './user.service';
import { HashService } from './hash.service';
import { TokensModule } from '../tokens';
import { RedisModule } from '../redis';
import { ApiToken } from '../tokens/entities';
import { CookiesModule } from '../cookies';
import { UsersController } from './users.controller';
import { config } from '../../config';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, ApiToken]),
    ClientsModule.register([
      {
        name: 'USERS_PACKAGE',
        transport: Transport.GRPC,
        options: {
          package: 'users',
          protoPath: path.join(__dirname, './users.grpc.proto'),
          url: config.grpcServerUrl,
        },
      },
    ]),
    RedisModule,
    TokensModule,
    CookiesModule,
  ],
  providers: [UserService, HashService],
  controllers: [UsersController],
  exports: [UserService],
})
export class UsersModule {}

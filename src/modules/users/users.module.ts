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
import { PACKAGE_NAME } from './users.grpc';
import { TracerProviderModule } from '../tracer';

@Module({
  imports: [
    TracerProviderModule.register(),
    TypeOrmModule.forFeature([User, ApiToken]),
    ClientsModule.register([
      {
        name: PACKAGE_NAME,
        transport: Transport.GRPC,
        options: {
          package: PACKAGE_NAME,
          protoPath: './src/modules/users/users.grpc.proto',
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

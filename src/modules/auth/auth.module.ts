import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';

import { CookiesModule } from '../cookies';
import { TokensModule } from '../tokens';
import { UsersModule } from '../users';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User, UserSchema } from '../users/schemas';

@Module({
  imports: [
    CookiesModule,
    TokensModule,
    UsersModule,
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  providers: [AuthService],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}

import { APP_PIPE } from '@nestjs/core';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Module, ValidationPipe } from '@nestjs/common';

import { TokensModule } from './modules/tokens';
import { AuthModule } from './modules/auth';
import { MfaModule } from './modules/mfa';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { databaseConfig } from './config';
import { TracerModule } from './modules/tracer';

@Module({
  imports: [
    TracerModule,
    TypeOrmModule.forRoot(databaseConfig),
    AuthModule,
    TokensModule,
    MfaModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_PIPE,
      useValue: new ValidationPipe({
        whitelist: true,
      }),
    },
  ],
})
export class AppModule {}

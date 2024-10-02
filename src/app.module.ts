import { Module, ValidationPipe } from '@nestjs/common';
import { APP_PIPE } from '@nestjs/core';
import { MongooseModule } from '@nestjs/mongoose';

import { TokensModule } from './modules/tokens';
import { AuthModule } from './modules/auth';
import { MfaModule } from './modules/mfa';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { getMongoUri } from './common/helpers';

@Module({
  imports: [
    MongooseModule.forRootAsync({
      useFactory: async () => {
        const uri = await getMongoUri();
        return { uri };
      },
    }),
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

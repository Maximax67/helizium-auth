import fastifyCookie from '@fastify/cookie';
import { NestFactory } from '@nestjs/core';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { AppModule } from './app.module';
import { GlobalExceptionFilter } from './common/filters';
import { config } from './config';
import { TracerModule } from './modules/tracer';
import { Logger } from 'pino-nestjs';

async function bootstrap() {
  TracerModule.initialize();

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
    { bufferLogs: true },
  );

  const logger = app.get(Logger);
  app.useLogger(logger);
  app.enableVersioning({
    type: VersioningType.URI,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  app.useGlobalFilters(new GlobalExceptionFilter());

  await app.register(fastifyCookie);

  async function gracefulShutdown() {
    logger.log('Shutdown signal received. Starting graceful shutdown...');
    try {
      await app.close();
      logger.log('Application shutdown complete.');
      process.exit(0);
    } catch (err) {
      logger.error('Error during shutdown', err);
      process.exit(1);
    }
  }

  process.on('SIGTERM', () => gracefulShutdown());
  process.on('SIGINT', () => gracefulShutdown());

  await app.listen({
    port: config.port,
    host: config.host || '0.0.0.0',
  });
}
bootstrap();

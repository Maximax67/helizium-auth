import {
  Controller,
  Get,
  HttpException,
  HttpStatus,
  VERSION_NEUTRAL,
} from '@nestjs/common';
import { DataSource } from 'typeorm';
import { AppService } from './app.service';

@Controller({ version: VERSION_NEUTRAL })
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly dataSource: DataSource,
  ) {}

  @Get()
  getApiInfo() {
    return this.appService.getApiInfo();
  }

  @Get('health')
  async healthCheck() {
    try {
      await this.dataSource.query('SELECT 1');
      return { status: 'ok' };
    } catch {
      throw new HttpException(
        { status: 'error', message: 'Database unavailable' },
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }
  }
}

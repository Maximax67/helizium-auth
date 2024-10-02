import { Injectable } from '@nestjs/common';
import { config } from './config';

@Injectable()
export class AppService {
  getApiInfo() {
    return {
      title: config.title,
      version: config.version,
      environment: config.nodeEnv,
    };
  }
}

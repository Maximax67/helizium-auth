import * as svgCaptcha from 'svg-captcha';
import { nanoid } from 'nanoid';
import { Injectable } from '@nestjs/common';
import { RedisService } from '../redis';
import { Captcha } from './interfaces';
import { config } from '../../config';

const captchaConfig = config.captcha;

@Injectable()
export class CaptchaService {
  constructor(private readonly redisService: RedisService) {}

  private readonly captchaOptions: svgCaptcha.ConfigObject = {
    size: captchaConfig.size,
    ignoreChars: captchaConfig.ignoreChars,
    noise: captchaConfig.noise,
  };

  private readonly forbiddenChars = new Set<string>(captchaConfig.ignoreChars);

  private getRedisKey(id: string): string {
    return `c:${id}`;
  }

  async create(): Promise<Captcha> {
    const id = nanoid();
    const redisKey = this.getRedisKey(id);
    const captcha = svgCaptcha.create(this.captchaOptions);

    const answer = captcha.text;

    await this.redisService.set(redisKey, answer, captchaConfig.ttl);

    return {
      id,
      answer,
      data: captcha.data,
    };
  }

  async validate(id: string, answer: string): Promise<boolean> {
    if (answer.length !== captchaConfig.size) {
      return false;
    }

    for (const char of answer) {
      if (this.forbiddenChars.has(char)) {
        return false;
      }
    }

    const redisKey = this.getRedisKey(id);
    const expectedAnswer = await this.redisService.get(redisKey);

    if (!expectedAnswer || expectedAnswer !== answer) {
      return false;
    }

    await this.redisService.delete(redisKey);

    return true;
  }
}

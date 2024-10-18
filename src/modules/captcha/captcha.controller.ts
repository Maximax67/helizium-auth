import {
  Controller,
  Get,
  Headers,
  HttpCode,
  Post,
  VERSION_NEUTRAL,
} from '@nestjs/common';
import { CaptchaService } from './captcha.service';
import { Serialize } from '../../common/interceptors';
import { CaptchaDto } from './dtos';
import { ApiError } from '../../common/errors';
import { Errors } from '../../common/constants';

@Controller({ path: 'captcha', version: VERSION_NEUTRAL })
export class CaptchaController {
  constructor(private readonly captchaService: CaptchaService) {}

  @Get()
  @Serialize(CaptchaDto)
  async create() {
    return this.captchaService.create();
  }

  @Post()
  @HttpCode(204)
  async validate(
    @Headers('captcha-id') captchaId: string,
    @Headers('captcha-answer') captchaAnswer: string,
  ) {
    if (!(await this.captchaService.validate(captchaId, captchaAnswer))) {
      throw new ApiError(Errors.CAPTCHA_INVALID_OR_EXPIRED);
    }
  }
}

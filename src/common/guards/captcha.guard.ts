import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { CaptchaService } from '../../modules/captcha';
import { ApiError } from '../errors';
import { Errors } from '../constants';

@Injectable()
export class CaptchaGuard implements CanActivate {
  constructor(private readonly captchaService: CaptchaService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    const captchaId = request.headers['captcha-id'];
    const captchaAnswer = request.headers['captcha-answer'];

    if (!captchaId || !captchaAnswer) {
      throw new ApiError(Errors.CAPTCHA_REQUIRED);
    }

    if (!(await this.captchaService.validate(captchaId, captchaAnswer))) {
      throw new ApiError(Errors.CAPTCHA_INVALID_OR_EXPIRED);
    }

    return true;
  }
}

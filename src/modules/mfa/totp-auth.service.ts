import { Injectable } from '@nestjs/common';

import { TotpService } from '../totp';
import { RedisService } from '../redis';
import { UserService } from '../users';
import { config } from '../../config';
import { ApiError } from '../../common/errors';
import { Errors } from '../../common/constants';

@Injectable()
export class TotpAuthService {
  constructor(
    private readonly totpService: TotpService,
    private readonly redisService: RedisService,
    private readonly userService: UserService,
  ) {}

  private getRedisTempTotpKey(userId: string): string {
    return `totp:${userId}`;
  }

  async initTotp(userId: string): Promise<string> {
    const storageKey = this.getRedisTempTotpKey(userId);
    const totp = this.totpService.initTotp();
    const secret = totp.secret.base32;

    await this.redisService.set(
      storageKey,
      secret,
      config.security.totpInitTtl,
    );

    return totp.toString();
  }

  async validateTotp(
    userId: string,
    token: string,
    isRoot: boolean,
  ): Promise<boolean> {
    const storageKey = this.getRedisTempTotpKey(userId);
    const redisSecret = await this.redisService.get(storageKey);

    if (redisSecret) {
      if (this.totpService.validateTotp(redisSecret, token)) {
        await this.redisService.delete(storageKey);
        await this.userService.setTotpSecret(userId, redisSecret);

        return true;
      }

      return false;
    }

    if (isRoot) {
      throw new ApiError(Errors.MFA_ALREADY_PASSED);
    }

    const secret = await this.userService.getTotpSecret(userId);

    return !!secret && this.totpService.validateTotp(secret, token);
  }

  async disableTotp(userId: string): Promise<void> {
    await this.userService.disableTotpMfa(userId);
  }
}

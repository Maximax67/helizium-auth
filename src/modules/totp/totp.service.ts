import * as OTPAuth from 'otpauth';
import { Injectable } from '@nestjs/common';
import { APP_NAME } from '../../common/constants';
import { config } from '../../config';

@Injectable()
export class TotpService {
  private readonly totpConfig = {
    issuer: APP_NAME,
    label: APP_NAME,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
  };

  private generateSecret(): OTPAuth.Secret {
    return new OTPAuth.Secret({ size: config.security.totpSecretSize });
  }

  private getNewTotp(secret: string | OTPAuth.Secret): OTPAuth.TOTP {
    return new OTPAuth.TOTP({
      ...this.totpConfig,
      secret,
    });
  }

  initTotp(): OTPAuth.TOTP {
    const secret = this.generateSecret();
    return this.getNewTotp(secret);
  }

  validateTotp(secret: string, token: string): boolean {
    const totp = this.getNewTotp(secret);
    return !!totp.validate({ token, window: 1 });
  }
}

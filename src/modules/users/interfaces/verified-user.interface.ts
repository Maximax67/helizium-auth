import { TokenLimits } from '../../../common/enums';
import { MfaInfo } from '../../../common/interfaces';

export interface VerifiedUser {
  userId: string;
  limits: TokenLimits;
  mfa: MfaInfo;
}

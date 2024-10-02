import { Types } from 'mongoose';
import { TokenLimits } from '../../../common/enums';
import { MfaInfo } from '../../../common/interfaces';

export interface VerifiedUser {
  userId: Types.ObjectId;
  limits: TokenLimits;
  mfa: MfaInfo;
}

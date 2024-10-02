import { GenerateTokenPayload } from './generate-token-payload.interface';
import { TokenLimits } from '../../../common/enums';

export interface TokenPayload extends GenerateTokenPayload {
  jti: string;
  limits: TokenLimits;
  [key: string]: any;
}

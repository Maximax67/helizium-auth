import { TokenTypes, TokenLimits } from '../enums';

export interface TokenInfo {
  type: TokenTypes;
  limits: TokenLimits;
  userId: string;
  jti: string;
  iat: number;
  exp: number;
  [key: string]: any;
}

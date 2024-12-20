import { TokenTypes, TokenLimits } from '../enums';

export interface Token {
  token: string;
  type: TokenTypes;
  limits: TokenLimits;
  userId: string;
  jti: string;
  iat: number;
  exp: number;
  [key: string]: any;
}

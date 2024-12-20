import { Expose } from 'class-transformer';
import { TokenLimits, TokenTypes } from '../../../common/enums';

export class TokenInfoDto {
  @Expose()
  type: TokenTypes;

  @Expose()
  limits: TokenLimits;

  @Expose()
  userId: string;

  @Expose()
  jti: string;

  @Expose()
  iat: number;

  @Expose()
  exp: number;
}

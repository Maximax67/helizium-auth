import { Expose } from 'class-transformer';
import { Jwk } from '../../../common/interfaces';

export class JwksDto {
  @Expose()
  keys: Jwk[];
}

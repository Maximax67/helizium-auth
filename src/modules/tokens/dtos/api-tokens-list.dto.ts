import { Expose, Type } from 'class-transformer';
import { ApiTokenDto } from './api-token.dto';

export class ApiTokensListDto {
  @Expose()
  @Type(() => ApiTokenDto)
  tokens: ApiTokenDto[];
}

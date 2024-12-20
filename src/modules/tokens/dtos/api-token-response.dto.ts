import { Expose } from 'class-transformer';

export class ApiTokenResponseDto {
  @Expose()
  token: string;
}

import { Expose, Transform } from 'class-transformer';

export class ApiTokenDto {
  @Expose()
  id: string;

  @Expose()
  @Transform(({ value }) => value?.substring(0, 6))
  jti: string;

  @Expose()
  title: string;

  @Expose()
  writeAccess: boolean;
}

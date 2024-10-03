import { Expose } from 'class-transformer';

export class ApiTokenDto {
  @Expose()
  jti: string;

  @Expose()
  title: string;

  @Expose()
  writeAccess: boolean;

  @Expose()
  createdAt: Date;
}

import { Expose } from 'class-transformer';

export class CaptchaDto {
  @Expose()
  id: string;

  @Expose()
  data: string;
}

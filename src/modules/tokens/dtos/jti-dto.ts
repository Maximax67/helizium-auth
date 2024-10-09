import { IsUUID } from 'class-validator';

export class JtiDto {
  @IsUUID(4)
  jti: string;
}

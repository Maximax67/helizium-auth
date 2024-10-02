import { IsMongoId, IsNotEmpty, IsString } from 'class-validator';

export class ConfirmEmailDto {
  @IsMongoId()
  userId: string;

  @IsString()
  @IsNotEmpty()
  code: string;
}

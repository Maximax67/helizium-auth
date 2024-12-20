import { IsBoolean, IsString, Length } from 'class-validator';

export class CreateApiTokenDto {
  @IsString()
  @Length(3, 20)
  title: string;

  @IsBoolean()
  writeAccess: boolean;
}

import { IsBoolean } from 'class-validator';

export class ChangeMfaRequiredDto {
  @IsBoolean()
  required: boolean;
}

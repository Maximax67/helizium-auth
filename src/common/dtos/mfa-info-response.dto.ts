import { Expose } from 'class-transformer';
import { MfaMethods } from '../enums';

export class MfaInfoResponseDto {
  @Expose()
  required: boolean;

  @Expose()
  methods: MfaMethods[];
}

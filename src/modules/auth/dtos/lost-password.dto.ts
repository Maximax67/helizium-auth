import { Matches } from 'class-validator';
import {
  EMAIL_REGEX,
  EMAIL_VALIDATOR_MESSAGE,
} from '../../../common/constants';
import { Transform } from 'class-transformer';

export class LostPasswordDto {
  @Matches(EMAIL_REGEX, {
    message: EMAIL_VALIDATOR_MESSAGE,
  })
  @Transform(({ value }) =>
    typeof value === 'string' ? value.toLowerCase() : value,
  )
  email: string;
}

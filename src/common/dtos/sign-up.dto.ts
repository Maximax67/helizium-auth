import { Transform } from 'class-transformer';
import { Matches, MaxLength } from 'class-validator';
import {
  EMAIL_REGEX,
  EMAIL_VALIDATOR_MESSAGE,
  PASSWORD_REGEX,
  PASSWORD_VALIDATOR_MESSAGE,
  USERNAME_REGEX,
  USERNAME_VALIDATOR_MESSAGE,
} from '../constants';

export class SignUpDto {
  @Matches(USERNAME_REGEX, {
    message: USERNAME_VALIDATOR_MESSAGE,
  })
  username: string;

  @Transform(({ value }) =>
    typeof value === 'string' ? value.toLowerCase() : value,
  )
  @MaxLength(254)
  @Matches(EMAIL_REGEX, {
    message: EMAIL_VALIDATOR_MESSAGE,
  })
  email: string;

  @Matches(PASSWORD_REGEX, {
    message: PASSWORD_VALIDATOR_MESSAGE,
  })
  password: string;
}

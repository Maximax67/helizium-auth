import { Transform } from 'class-transformer';
import { Matches, MaxLength } from 'class-validator';
import { EMAIL_REGEX, PASSWORD_REGEX, USERNAME_REGEX } from '../constants';

export class SignUpDto {
  @Matches(USERNAME_REGEX, {
    message:
      'Username should be 4-30 characters long and contain only English letters, digits and underscores.',
  })
  username: string;

  @Transform(({ value }) =>
    typeof value === 'string' ? value.toLowerCase() : value,
  )
  @MaxLength(254)
  @Matches(EMAIL_REGEX, {
    message: 'Email is not valid.',
  })
  email: string;

  @Matches(PASSWORD_REGEX, {
    message:
      'Password must be 8-32 characters long and contain at least one lowercase letter, one uppercase letter, and one digit. Special characters are allowed but not required.',
  })
  password: string;
}

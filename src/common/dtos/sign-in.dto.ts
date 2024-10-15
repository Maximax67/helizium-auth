import { Matches } from 'class-validator';
import { LOGIN_REGEX, PASSWORD_REGEX } from '../constants';

export class SignInDto {
  @Matches(LOGIN_REGEX, {
    message: 'Login should be valid username or email.',
  })
  login: string;

  @Matches(PASSWORD_REGEX, {
    message:
      'Password must be 8-32 characters long and contain at least one lowercase letter, one uppercase letter, and one digit. Special characters are allowed but not required.',
  })
  password: string;
}

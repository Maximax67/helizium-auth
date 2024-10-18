import { Matches } from 'class-validator';
import {
  LOGIN_REGEX,
  LOGIN_VALIDATOR_MESSAGE,
  PASSWORD_REGEX,
  PASSWORD_VALIDATOR_MESSAGE,
} from '../constants';

export class SignInDto {
  @Matches(LOGIN_REGEX, {
    message: LOGIN_VALIDATOR_MESSAGE,
  })
  login: string;

  @Matches(PASSWORD_REGEX, {
    message: PASSWORD_VALIDATOR_MESSAGE,
  })
  password: string;
}

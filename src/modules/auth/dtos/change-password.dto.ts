import { Matches } from 'class-validator';
import {
  PASSWORD_REGEX,
  PASSWORD_VALIDATOR_MESSAGE,
} from '../../../common/constants';

export class ChangePasswordDto {
  @Matches(PASSWORD_REGEX, {
    message: PASSWORD_VALIDATOR_MESSAGE,
  })
  oldPassword: string;

  @Matches(PASSWORD_REGEX, {
    message: PASSWORD_VALIDATOR_MESSAGE,
  })
  newPassword: string;
}

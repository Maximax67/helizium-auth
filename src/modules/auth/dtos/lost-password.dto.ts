import { Matches } from 'class-validator';
import {
  EMAIL_REGEX,
  EMAIL_VALIDATOR_MESSAGE,
} from '../../../common/constants';

export class LostPasswordDto {
  @Matches(EMAIL_REGEX, {
    message: EMAIL_VALIDATOR_MESSAGE,
  })
  email: string;
}

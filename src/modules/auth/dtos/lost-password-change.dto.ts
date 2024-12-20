import { IsMongoId, Matches } from 'class-validator';
import {
  INVALID_RESET_PASSWORD_TOKEN_VALIDATOR_MESSAGE,
  NANOID_REGEX,
  PASSWORD_REGEX,
  PASSWORD_VALIDATOR_MESSAGE,
} from '../../../common/constants';

export class LostPasswordChangeDto {
  @IsMongoId()
  userId: string;

  @Matches(NANOID_REGEX, {
    message: INVALID_RESET_PASSWORD_TOKEN_VALIDATOR_MESSAGE,
  })
  token: string;

  @Matches(PASSWORD_REGEX, {
    message: PASSWORD_VALIDATOR_MESSAGE,
  })
  password: string;
}

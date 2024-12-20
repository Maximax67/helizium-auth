import { IsMongoId, Matches } from 'class-validator';
import {
  INVALID_RESET_PASSWORD_TOKEN_VALIDATOR_MESSAGE,
  NANOID_REGEX,
} from '../../../common/constants';

export class LostPasswordVerifyDto {
  @IsMongoId()
  userId: string;

  @Matches(NANOID_REGEX, {
    message: INVALID_RESET_PASSWORD_TOKEN_VALIDATOR_MESSAGE,
  })
  token: string;
}

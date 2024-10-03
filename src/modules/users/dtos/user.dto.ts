import { Expose } from 'class-transformer';

export class UserDto {
  @Expose()
  id: string;

  @Expose()
  username: string;

  @Expose()
  email: string;

  @Expose()
  isBanned: boolean;

  @Expose()
  isMfaRequired: boolean;

  @Expose()
  isEmailConfirmed: boolean;

  @Expose()
  createdAt: Date;

  @Expose()
  updatedAt: Date;
}

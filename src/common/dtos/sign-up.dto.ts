import { Transform } from 'class-transformer';
import { Length, Matches, MaxLength } from 'class-validator';

export class SignUpDto {
  @Length(4, 16)
  @Matches(/^[a-zA-Z0-9_]/, {
    message:
      'Username can contain only English letters, digits and underscores.',
  })
  username: string;

  @Transform(({ value }) =>
    typeof value === 'string' ? value.toLowerCase() : value,
  )
  @MaxLength(254)
  @Matches(/^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/, {
    message: 'Email is not valid.',
  })
  email: string;

  @Length(8, 24)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).*$/, {
    message:
      'Password must contain at least one lowercase letter, one uppercase letter, and one special character.',
  })
  password: string;
}

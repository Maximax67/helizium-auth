import { Length, Matches } from 'class-validator';

export class SignInDto {
  @Matches(
    /^(?=.{4,254}$)([a-zA-Z0-9_]{4,16}|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$/,
    {
      message: 'Login should be valid username or email.',
    },
  )
  login: string;

  @Length(8, 24)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).*$/, {
    message:
      'Password must contain at least one lowercase letter, one uppercase letter, and one special character.',
  })
  password: string;
}

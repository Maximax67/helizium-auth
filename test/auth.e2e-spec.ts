import axios from 'axios';
import { faker } from '@faker-js/faker';
import { Test, TestingModule } from '@nestjs/testing';
import { DataSource } from 'typeorm';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import {
  CookieNames,
  EmailTemplatesEnum,
  MfaMethods,
  TokenLimits,
} from '../src/common/enums';
import {
  generateObjectId,
  generatePassword,
  generateUsername,
} from '../src/common/helpers';
import { USERS_PACKAGE_NAME, UserService } from '../src/modules/users';
import { AuthModule } from '../src/modules/auth';
import { APP_PIPE } from '@nestjs/core';
import { HttpStatus, ValidationPipe } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { config, databaseConfig } from '../src/config';
import { of } from 'rxjs';
import fastifyCookie from '@fastify/cookie';
import { Errors } from '../src/common/constants';
import { EmailTemplateSubjects } from '../src/modules/mail/interfaces';
import { MailService } from '../src/modules/mail';
import { MfaModule } from '../src/modules/mfa';
import { RedisService } from '../src/modules/redis';
import { TotpService } from '../src/modules/totp';
import { nanoid } from 'nanoid';

jest.mock('axios');

interface MailOption {
  to: string;
  subject: string;
  context: {
    otp: string;
    [key: string]: any;
  };
}

const sentMailOptions = [] as MailOption[];

const mockTransporter = {
  sendMail: jest.fn((mailOptions) => {
    sentMailOptions.push(mailOptions);
    return Promise.resolve({ messageId: 'mocked-message-id' });
  }),
};

describe('AuthController (e2e)', () => {
  let app: NestFastifyApplication;
  let userService: UserService;
  let redisService: RedisService;
  let totpService: TotpService;

  let userEmail: string;
  let userUsername: string;
  let userPassword: string;

  let userAccessToken: string;
  let userRefreshToken: string;
  let emailToken: string;

  let user1Email: string,
    user1Password: string,
    user1AccessToken: string,
    user1EmailToken: string;
  let user2Email: string,
    user2Password: string,
    user2AccessToken: string,
    user2EmailToken: string;
  let user3Email: string,
    user3Password: string,
    user3AccessToken: string,
    user3EmailToken: string;

  const mockUserGrpcClient = {
    signUp: jest.fn(() => of({ userId: generateObjectId() })),
    banUser: jest.fn(() => of({})),
    unbanUser: jest.fn(() => of({})),
    deleteUser: jest.fn(() => of({})),
  };

  beforeAll(async () => {
    const mockClientGrpc = {
      getService: jest.fn(() => mockUserGrpcClient),
    };

    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [TypeOrmModule.forRoot(databaseConfig), AuthModule, MfaModule],
      providers: [
        {
          provide: APP_PIPE,
          useValue: new ValidationPipe({
            whitelist: true,
          }),
        },
        {
          provide: 'NODEMAIL_TRANSPORTER',
          useValue: mockTransporter,
        },
      ],
    })
      .overrideProvider(MailService)
      .useFactory({
        factory: () => new MailService(mockTransporter as any),
      })
      .overrideProvider(USERS_PACKAGE_NAME)
      .useValue(mockClientGrpc)
      .compile();

    app = moduleRef.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );

    app.register(fastifyCookie);

    userService = moduleRef.get<UserService>(UserService);
    redisService = moduleRef.get<RedisService>(RedisService);
    totpService = moduleRef.get<TotpService>(TotpService);

    jest.spyOn(totpService, 'validateTotp');

    await app.init();
    await app.getHttpAdapter().getInstance().ready();

    // User 1 Setup
    user1Email = faker.internet.email();
    user1Password = generatePassword();
    user1AccessToken = await signUpAndLoginUser(user1Email, user1Password);

    user1EmailToken = await sendEmailOtp(user1AccessToken);

    // User 2 Setup
    user2Email = faker.internet.email();
    user2Password = generatePassword();
    user2AccessToken = await signUpAndLoginUser(user2Email, user2Password);

    user2EmailToken = await sendEmailOtp(user2AccessToken);

    // User 3 Setup
    user3Email = faker.internet.email();
    user3Password = generatePassword();
    user3AccessToken = await signUpAndLoginUser(user3Email, user3Password);

    user3EmailToken = await sendEmailOtp(user3AccessToken);
  });

  async function signUpAndLoginUser(
    email: string,
    password: string,
  ): Promise<string> {
    const signUpResult = await app.inject({
      method: 'POST',
      url: '/auth/signup',
      payload: { email, username: generateUsername(), password },
    });

    const loginCookies = signUpResult.cookies;
    const accessToken = loginCookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    )?.value;

    const token = accessToken!;
    return token;
  }

  async function sendEmailOtp(accessToken: string): Promise<string> {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/send-code',
      cookies: { [CookieNames.ACCESS_TOKEN]: accessToken },
    });

    const cookies = result.cookies;
    return cookies.find(
      (cookie) => cookie.name === CookieNames.EMAIL_CONFIRM_TOKEN,
    )!.value;
  }

  it('/auth/mfa/email/confirm (POST) - should confirm email for User 1 from a different session', async () => {
    const newSessionResult = await app.inject({
      method: 'POST',
      url: '/auth/sign',
      payload: {
        login: user1Email,
        password: user1Password,
      },
    });

    expect(newSessionResult.statusCode).toBe(200);
    const newSessionPayload = JSON.parse(newSessionResult.payload);
    expect(newSessionPayload.required).toBe(false);

    const cookies = newSessionResult.cookies;
    const sessionCookies = cookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    )?.value;
    const newSessionToken = sessionCookies!;

    const lastMailOptions = sentMailOptions.find(
      (mail) => mail.to === user1Email.toLowerCase(),
    );
    const validOtp = lastMailOptions?.context.otp;
    const res = await userService.getIdAndUsernameByEmail(
      user1Email.toLowerCase(),
    );

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/confirm',
      payload: { userId: res?.id.toString('hex'), code: validOtp },
      cookies: {
        [CookieNames.ACCESS_TOKEN]: newSessionToken,
        [CookieNames.EMAIL_CONFIRM_TOKEN]: user1EmailToken,
      },
    });

    expect(result.statusCode).toBe(HttpStatus.OK);
    const payload = JSON.parse(result.payload);
    expect(payload).toHaveProperty('isTokenVerifyRequired', false);
  });

  it('/auth/mfa/email/confirm (POST) - should fail confirmation for User 2 without session', async () => {
    const lastMailOptions = sentMailOptions.find(
      (mail) => mail.to === user2Email.toLowerCase(),
    );
    const validOtp = lastMailOptions?.context.otp;
    const res = await userService.getIdAndUsernameByEmail(
      user2Email.toLowerCase(),
    );

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/confirm',
      payload: { userId: res?.id.toString('hex'), code: validOtp },
    });

    expect(result.statusCode).toBe(HttpStatus.OK);
    const payload = JSON.parse(result.payload);
    expect(payload).toHaveProperty('isTokenVerifyRequired', true);
  });

  it('/auth/jwks (GET) should return JWKS', async () => {
    const result = await app.inject({
      method: 'GET',
      url: '/auth/jwks',
    });

    expect(result.statusCode).toEqual(200);

    const payload = JSON.parse(result.payload);
    expect(payload).toHaveProperty('keys');
    expect(Array.isArray(payload.keys)).toBeTruthy();
  });

  it('/auth/signup (POST) - should fail to sign up if required fields are missing', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/signup',
      payload: {
        email: faker.internet.email(),
      },
    });

    expect(result.statusCode).toEqual(HttpStatus.BAD_REQUEST);
  });

  it('/auth/info (GET) should fail to check limits with no jwt token provided', async () => {
    const result = await app.inject({
      method: 'GET',
      url: '/auth/info',
    });

    expect(result.statusCode).toBe(Errors.JWT_TOKEN_INVALID.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toBe(Errors.JWT_TOKEN_INVALID.message);
  });

  it('/auth/signup (POST) should sign up a user', async () => {
    const email = faker.internet.email();
    const username = generateUsername();
    const password = generatePassword();

    const result = await app.inject({
      method: 'POST',
      url: '/auth/signup',
      payload: {
        email,
        username,
        password,
      },
    });

    expect(result.payload).toBe('');
    expect(result.statusCode).toEqual(201);
    expect(mockUserGrpcClient.signUp).toHaveBeenCalled();

    expect(result.cookies).toBeDefined();

    const cookies = result.cookies;

    const accessToken = cookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    )?.value;
    const refreshToken = cookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    )?.value;

    expect(accessToken).toBeDefined();
    expect(refreshToken).toBeDefined();

    userEmail = email;
    userUsername = username;
    userPassword = password;

    userAccessToken = accessToken!;
    userRefreshToken = refreshToken!;
  });

  it('/auth/info (GET) should check if limits are correctly set', async () => {
    const result = await app.inject({
      method: 'GET',
      url: '/auth/info',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(result.statusCode).toBe(HttpStatus.OK);
    const payload = JSON.parse(result.payload);
    expect(payload.limits).toBe(TokenLimits.EMAIL_NOT_CONFIRMED);
  });

  it('/auth/mfa (POST) should fail to change mfa required with no jwt token provided', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa',
      payload: { required: true },
    });

    expect(result.statusCode).toBe(Errors.JWT_TOKEN_INVALID.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toBe(Errors.JWT_TOKEN_INVALID.message);
  });

  it('/auth/signup (POST) - should fail to sign up if email/username already exists', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/signup',
      payload: {
        email: userEmail,
        username: userUsername,
        password: userPassword,
      },
    });

    expect(result.statusCode).toEqual(Errors.USER_ALREADY_EXISTS.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(Errors.USER_ALREADY_EXISTS.message);
  });

  it('/auth/sign (POST) - should fail to sign in with incorrect email/username', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/sign',
      payload: {
        login: 'nonexistent@example.com',
        password: generatePassword(),
      },
    });

    expect(result.statusCode).toBe(Errors.INVALID_CREDENTIALS.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(Errors.INVALID_CREDENTIALS.message);
  });

  it('/auth/info (GET) - should return 401 when accessing without token', async () => {
    const result = await app.inject({
      method: 'GET',
      url: '/auth/info',
    });

    expect(result.statusCode).toBe(Errors.JWT_TOKEN_INVALID.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(Errors.JWT_TOKEN_INVALID.message);
  });

  it('/auth/refresh (POST) - should fail to refresh with an invalid token', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      cookies: {
        [CookieNames.REFRESH_TOKEN]: 'invalid-refresh-token',
      },
    });

    expect(result.statusCode).toBe(Errors.REFRESH_TOKEN_INVALID.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(Errors.REFRESH_TOKEN_INVALID.message);
  });

  it('/auth/logout (POST) - should log out the user', async () => {
    const axiosPostMock = jest.spyOn(axios, 'post').mockResolvedValue({});

    const result = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(result.statusCode).toBe(204);

    const cookies = result.cookies;
    const accessTokenCookie = cookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    );
    const refreshTokenCookie = cookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    );

    expect(accessTokenCookie?.value).toBe('');
    expect(refreshTokenCookie?.value).toBe('');

    expect(axiosPostMock).toHaveBeenCalledWith(
      config.apiGatewayTokenRevokeUrl,
      { jti: expect.any(String) },
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    );
  });

  it('/auth/info (GET) - should return 401 when using a revoked token', async () => {
    const result = await app.inject({
      method: 'GET',
      url: '/auth/info',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(result.statusCode).toBe(Errors.JWT_TOKEN_INVALID.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(Errors.JWT_TOKEN_INVALID.message);
  });

  it('/auth/logout (POST) - should return 401 when accessing without token', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/logout',
    });

    expect(result.statusCode).toBe(Errors.JWT_TOKEN_INVALID.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(Errors.JWT_TOKEN_INVALID.message);
  });

  it('/auth/sign (POST) should sign in a user by email', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/sign',
      payload: {
        login: userEmail,
        password: userPassword,
      },
    });

    expect(result.payload).toBeDefined();
    expect(result.statusCode).toEqual(200);

    const payload = JSON.parse(result.payload);

    expect(payload.required).toBe(false);
    expect(payload.methods).toStrictEqual([MfaMethods.EMAIL]);

    expect(result.cookies).toBeDefined();

    const cookies = result.cookies;

    const accessToken = cookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    )?.value;
    const refreshToken = cookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    )?.value;

    expect(accessToken).toBeDefined();
    expect(refreshToken).toBeDefined();

    userAccessToken = accessToken!;
    userRefreshToken = refreshToken!;
  });

  it('/auth/sign (POST) should sign in a user by username', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/sign',
      payload: {
        login: userUsername,
        password: userPassword,
      },
    });

    expect(result.payload).toBeDefined();
    expect(result.statusCode).toEqual(200);

    const payload = JSON.parse(result.payload);

    expect(payload.required).toBe(false);
    expect(payload.methods).toStrictEqual([MfaMethods.EMAIL]);

    expect(result.cookies).toBeDefined();

    const cookies = result.cookies;

    const accessToken = cookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    )?.value;
    const refreshToken = cookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    )?.value;

    expect(accessToken).toBeDefined();
    expect(refreshToken).toBeDefined();

    userAccessToken = accessToken!;
    userRefreshToken = refreshToken!;
  });

  it('/auth/mfa/email/confirm (POST) - should fail when User 3 attempts to confirm User 1’s OTP', async () => {
    const lastMailOptions = sentMailOptions.find(
      (mail) => mail.to === user3Email.toLowerCase(),
    );
    const validOtp = lastMailOptions?.context.otp;
    const res = await userService.getIdAndUsernameByEmail(
      user3Email.toLowerCase(),
    );

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/confirm',
      payload: { userId: res?.id.toString('hex'), code: validOtp },
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(result.statusCode).toBe(HttpStatus.OK);
    const payload = JSON.parse(result.payload);
    expect(payload).toHaveProperty('isTokenVerifyRequired', true);
  });

  it('/auth/terminate (POST) - should return 401 if access token is invalid', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/terminate',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: 'invalid-access-token',
      },
    });

    expect(result.statusCode).toBe(Errors.JWT_TOKEN_INVALID.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(Errors.JWT_TOKEN_INVALID.message);
  });

  it('/auth/terminate (POST) - should terminate all sessions for the user', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/terminate',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(result.statusCode).toBe(204);

    const cookies = result.cookies;

    const accessTokenCookie = cookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    );
    const refreshTokenCookie = cookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    );

    expect(accessTokenCookie?.value).toBe('');
    expect(refreshTokenCookie?.value).toBe('');
  });

  it('/auth/sign (POST) - should return error with invalid password', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/sign',
      payload: { login: userEmail, password: userPassword.substring(1) + '1' },
    });

    expect(result.statusCode).toBe(401);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toBeDefined();
    expect(payload.message).toContain('Invalid credentials');
  });

  it('/auth/refresh (POST) - should refresh the user tokens', async () => {
    const loginResult = await app.inject({
      method: 'POST',
      url: '/auth/sign',
      payload: {
        login: userEmail,
        password: userPassword,
      },
    });

    expect(loginResult.statusCode).toBe(200);

    const loginCookies = loginResult.cookies;

    const accessToken = loginCookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    )?.value;
    const refreshToken = loginCookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    )?.value;

    expect(accessToken).toBeDefined();
    expect(refreshToken).toBeDefined();

    userAccessToken = accessToken!;
    userRefreshToken = refreshToken!;

    const result = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      cookies: {
        [CookieNames.REFRESH_TOKEN]: userRefreshToken,
      },
    });

    expect(result.statusCode).toBe(200);

    const cookies = result.cookies;

    const accessTokenCookie = cookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    );
    const refreshTokenCookie = cookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    );

    expect(accessTokenCookie?.value).toBeDefined();
    expect(refreshTokenCookie?.value).toBeDefined();

    userAccessToken = accessTokenCookie!.value;
    userRefreshToken = refreshTokenCookie!.value;
  });

  it('/auth/mfa (GET) - should return available MFA methods for user', async () => {
    const result = await app.inject({
      method: 'GET',
      url: '/auth/mfa',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(result.statusCode).toBe(200);
    const payload = JSON.parse(result.payload);
    expect(payload).toHaveProperty('methods');
    expect(Array.isArray(payload.methods)).toBeTruthy();

    expect(payload.methods).not.toContain('TOTP');
    expect(payload.methods).toContain('EMAIL');
  });

  it('/auth/mfa/email/send-code (POST) - should send MFA email code to the correct user', async () => {
    const expectedTemplate = EmailTemplatesEnum.CONFIRM_EMAIL;

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/send-code',
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(result.statusCode).toBe(HttpStatus.CREATED);
    expect(mockTransporter.sendMail).toHaveBeenCalled();

    const mailOptions = sentMailOptions[sentMailOptions.length - 1];
    expect(mailOptions).toMatchObject({
      from: config.email.from,
      to: userEmail.toLowerCase(),
      subject: expect.any(String),
      template: expectedTemplate,
      context: {
        appName: 'Helizium',
        username: expect.any(String),
        otp: expect.any(String),
      },
    });

    const sentOtp = mailOptions.context.otp;
    expect(sentOtp).toBeDefined();

    const cookies = result.cookies;

    const emailCookieToken = cookies.find(
      (cookie) => cookie.name === CookieNames.EMAIL_CONFIRM_TOKEN,
    );

    emailToken = emailCookieToken!.value;
  });

  it('/auth/mfa/email/cancel (DELETE) - should not cancel email confirmation without email token', async () => {
    const result = await app.inject({
      method: 'DELETE',
      url: '/auth/mfa/email/cancel',
      cookies: {
        [CookieNames.EMAIL_CONFIRM_TOKEN]: emailToken,
      },
    });

    expect(result.statusCode).toBe(Errors.JWT_TOKEN_INVALID.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toBeDefined();
    expect(payload.message).toContain(Errors.JWT_TOKEN_INVALID.message);
  });

  it('/auth/mfa/email/cancel (DELETE) - should cancel email confirmation', async () => {
    const result = await app.inject({
      method: 'DELETE',
      url: '/auth/mfa/email/cancel',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
        [CookieNames.EMAIL_CONFIRM_TOKEN]: emailToken,
      },
    });

    expect(result.statusCode).toBe(204);
  });

  it('/auth/mfa/email/confirm (POST) - should not confirm valid MFA email after mfa cancel', async () => {
    const lastMailOptions = sentMailOptions[sentMailOptions.length - 1];
    const validOtp = lastMailOptions.context.otp;
    const res = await userService.getIdAndUsernameByEmail(
      userEmail.toLowerCase(),
    );

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/confirm',
      payload: { userId: res?.id.toString('hex'), code: validOtp },
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(result.statusCode).toBe(Errors.EMAIL_CONFIRMATION_INVALID.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toBeDefined();
    expect(payload.message).toContain(
      Errors.EMAIL_CONFIRMATION_INVALID.message,
    );
  });

  it('/auth/mfa/email/send-code (POST) - should send MFA email code to the correct user second time', async () => {
    const expectedTemplate = EmailTemplatesEnum.CONFIRM_EMAIL;

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/send-code',
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(result.statusCode).toBe(HttpStatus.CREATED);
    expect(mockTransporter.sendMail).toHaveBeenCalled();

    const mailOptions = sentMailOptions[sentMailOptions.length - 1];
    expect(mailOptions).toMatchObject({
      from: config.email.from,
      to: userEmail.toLowerCase(),
      subject: expect.any(String),
      template: expectedTemplate,
      context: {
        appName: 'Helizium',
        username: expect.any(String),
        otp: expect.any(String),
      },
    });

    const sentOtp = mailOptions.context.otp;
    expect(sentOtp).toBeDefined();

    const cookies = result.cookies;

    const emailCookieToken = cookies.find(
      (cookie) => cookie.name === CookieNames.EMAIL_CONFIRM_TOKEN,
    );

    emailToken = emailCookieToken!.value;
  });

  it('/auth/mfa/email/verify (GET) - should have cookie token missing error', async () => {
    const result = await app.inject({
      method: 'GET',
      url: '/auth/mfa/email/verify',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
        // [CookieNames.EMAIL_CONFIRM_TOKEN]: emailToken,
      },
    });

    expect(result.statusCode).toBe(Errors.COOKIE_TOKEN_MISSING.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toBeDefined();
    expect(payload.message).toContain(Errors.COOKIE_TOKEN_MISSING.message);
  });

  it('/auth/mfa/email/verify (GET) - should have invalid email token error', async () => {
    const result = await app.inject({
      method: 'GET',
      url: '/auth/mfa/email/verify',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
        [CookieNames.EMAIL_CONFIRM_TOKEN]: emailToken,
      },
    });

    expect(result.statusCode).toBe(HttpStatus.OK);
    const payload = JSON.parse(result.payload);
    expect(payload).toHaveProperty('confirmed', false);
  });

  it('/auth/mfa/email/confirm (POST) - should fail with an invalid MFA email code', async () => {
    const invalidOtp = '0000000';

    const res = await userService.getIdAndUsernameByEmail(
      userEmail.toLowerCase(),
    );

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/confirm',
      payload: { userId: res?.id.toString('hex'), code: invalidOtp },
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
        [CookieNames.EMAIL_CONFIRM_TOKEN]: emailToken,
      },
    });

    expect(result.statusCode).toBe(Errors.EMAIL_CONFIRMATION_INVALID.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(
      Errors.EMAIL_CONFIRMATION_INVALID.message,
    );
  });

  it('/auth/mfa/email/confirm (POST) - should confirm valid MFA email code', async () => {
    const lastMailOptions = sentMailOptions[sentMailOptions.length - 1];
    const validOtp = lastMailOptions.context.otp;
    const res = await userService.getIdAndUsernameByEmail(
      userEmail.toLowerCase(),
    );

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/confirm',
      payload: { userId: res?.id.toString('hex'), code: validOtp },
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
        [CookieNames.EMAIL_CONFIRM_TOKEN]: emailToken,
      },
    });

    expect(result.statusCode).toBe(HttpStatus.OK);
    const payload = JSON.parse(result.payload);
    expect(payload).toHaveProperty('isTokenVerifyRequired', false);
  });

  it('/auth/mfa/email/verify (GET) - access should be forbidden after email confirmation', async () => {
    const refResult = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      cookies: {
        [CookieNames.REFRESH_TOKEN]: userRefreshToken,
      },
    });

    expect(refResult.statusCode).toBe(200);

    const cookies = refResult.cookies;

    const accessTokenCookie = cookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    );
    const refreshTokenCookie = cookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    );

    expect(accessTokenCookie?.value).toBeDefined();
    expect(refreshTokenCookie?.value).toBeDefined();

    userAccessToken = accessTokenCookie!.value;
    userRefreshToken = refreshTokenCookie!.value;

    const result = await app.inject({
      method: 'GET',
      url: '/auth/mfa/email/verify',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(result.statusCode).toBe(Errors.FORBIDDEN_WITH_TOKEN_LIMITS.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toBeDefined();
    expect(payload.message).toContain(
      Errors.FORBIDDEN_WITH_TOKEN_LIMITS.message,
    );
  });

  it('/auth/info (GET) should check if limits are correctly set to ROOT after email confirmation', async () => {
    const result = await app.inject({
      method: 'GET',
      url: '/auth/info',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(result.statusCode).toBe(HttpStatus.OK);
    const payload = JSON.parse(result.payload);
    expect(payload.limits).toBe(TokenLimits.ROOT);
  });

  it('/auth/mfa/totp/init (POST) - should initialize TOTP and return URI', async () => {
    const res = await userService.getIdAndUsernameByEmail(
      userEmail.toLowerCase(),
    );
    const userId = res?.id.toString('hex');

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/totp/init',
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(result.statusCode).toBe(HttpStatus.CREATED);
    const payload = JSON.parse(result.payload);
    expect(payload).toHaveProperty('uri');
    expect(typeof payload.uri).toBe('string');

    const redisSecret = await redisService.get(`totp:${userId}`);
    expect(redisSecret).toBeDefined();
  });

  it('/auth/mfa/totp/confirm (POST) - should fail with an invalid TOTP code', async () => {
    const invalidTotpToken = '123456';

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/totp/confirm',
      payload: { token: invalidTotpToken },
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(result.statusCode).toBe(Errors.INVALID_TOTP.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(Errors.INVALID_TOTP.message);
  });

  it('/auth/mfa/totp/confirm (POST) - should confirm TOTP with valid code', async () => {
    const res = await userService.getIdAndUsernameByEmail(
      userEmail.toLowerCase(),
    );
    const userId = res?.id.toString('hex');

    (totpService.validateTotp as jest.Mock).mockReturnValueOnce(true);

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/totp/confirm',
      payload: { token: 'valid-totp-token' },
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(result.statusCode).toBe(HttpStatus.NO_CONTENT);
    const redisSecret = await redisService.get(`totp:${userId}`);
    expect(redisSecret).toBeUndefined();
  });

  it('/auth/mfa/totp (DELETE) - should disable TOTP MFA', async () => {
    const result = await app.inject({
      method: 'DELETE',
      url: '/auth/mfa/totp',
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(result.statusCode).toBe(HttpStatus.NO_CONTENT);

    const methodsResult = await app.inject({
      method: 'GET',
      url: '/auth/mfa',
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(methodsResult.statusCode).toBe(HttpStatus.OK);

    const payload = JSON.parse(methodsResult.payload);
    expect(payload).toHaveProperty('methods');
    expect(Array.isArray(payload.methods)).toBeTruthy();

    expect(payload.methods).not.toContain('TOTP');
    expect(payload.methods).toContain('EMAIL');
  });

  it('/auth/mfa (POST) should change mfa required to be true', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa',
      payload: { required: true },
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(result.statusCode).toBe(HttpStatus.NO_CONTENT);

    const logoutResult = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(logoutResult.statusCode).toBe(HttpStatus.NO_CONTENT);

    const loginResult = await app.inject({
      method: 'POST',
      url: '/auth/sign',
      payload: {
        login: userEmail,
        password: userPassword,
      },
    });

    expect(loginResult.statusCode).toBe(HttpStatus.OK);

    const loginCookies = loginResult.cookies;

    const newAccessToken = loginCookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    )?.value;

    const newRefreshToken = loginCookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    )?.value;

    expect(newAccessToken).toBeDefined();
    expect(newRefreshToken).toBeDefined();

    userAccessToken = newAccessToken!;
    userRefreshToken = newRefreshToken!;

    const mfaStatusResult = await app.inject({
      method: 'GET',
      url: '/auth/mfa',
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(mfaStatusResult.statusCode).toBe(HttpStatus.OK);

    const mfaPayload = JSON.parse(mfaStatusResult.payload);
    expect(mfaPayload).toHaveProperty('required', true);
    expect(Array.isArray(mfaPayload.methods)).toBe(true);

    const authInfoResult = await app.inject({
      method: 'GET',
      url: '/auth/info',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(authInfoResult.statusCode).toBe(HttpStatus.OK);
    const payload = JSON.parse(authInfoResult.payload);
    expect(payload.limits).toBe(TokenLimits.MFA_REQUIRED);
  });

  it('/auth/mfa/email/send-code (POST) - 123123123123', async () => {
    const expectedTemplate = EmailTemplatesEnum.MFA_EMAIL;

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/send-code',
      cookies: { [CookieNames.ACCESS_TOKEN]: userAccessToken },
    });

    expect(result.statusCode).toBe(HttpStatus.CREATED);
    expect(mockTransporter.sendMail).toHaveBeenCalled();

    const mailOptions = sentMailOptions[sentMailOptions.length - 1];
    expect(mailOptions).toMatchObject({
      from: config.email.from,
      to: userEmail.toLowerCase(),
      subject: expect.any(String),
      template: expectedTemplate,
      context: {
        appName: 'Helizium',
        username: expect.any(String),
        otp: expect.any(String),
      },
    });

    const sentOtp = mailOptions.context.otp;
    expect(sentOtp).toBeDefined();

    const cookies = result.cookies;

    const emailCookieToken = cookies.find(
      (cookie) => cookie.name === CookieNames.EMAIL_CONFIRM_TOKEN,
    );

    emailToken = emailCookieToken!.value;
  });

  it('/auth/mfa/email/confirm (POST) - 2222222222', async () => {
    const lastMailOptions = sentMailOptions[sentMailOptions.length - 1];
    const validOtp = lastMailOptions.context.otp;
    const res = await userService.getIdAndUsernameByEmail(
      userEmail.toLowerCase(),
    );

    const result = await app.inject({
      method: 'POST',
      url: '/auth/mfa/email/confirm',
      payload: { userId: res?.id.toString('hex'), code: validOtp },
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
        [CookieNames.EMAIL_CONFIRM_TOKEN]: emailToken,
      },
    });

    expect(result.statusCode).toBe(HttpStatus.OK);
    const payload = JSON.parse(result.payload);
    expect(payload).toHaveProperty('isTokenVerifyRequired', false);

    const refreshResult = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      cookies: {
        [CookieNames.REFRESH_TOKEN]: userRefreshToken,
      },
    });

    expect(refreshResult.statusCode).toBe(HttpStatus.OK);

    const refreshCookies = refreshResult.cookies;
    const newAccessToken = refreshCookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    )?.value;
    const newRefreshToken = refreshCookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    )?.value;

    expect(newAccessToken).toBeDefined();
    expect(newRefreshToken).toBeDefined();

    userAccessToken = newAccessToken!;
    userRefreshToken = newRefreshToken!;

    const authInfoResult = await app.inject({
      method: 'GET',
      url: '/auth/info',
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
        [CookieNames.EMAIL_CONFIRM_TOKEN]: emailToken,
      },
    });

    expect(authInfoResult.statusCode).toBe(HttpStatus.OK);
    const authPayload = JSON.parse(authInfoResult.payload);
    expect(authPayload.limits).toBe(TokenLimits.ROOT);
  });

  it('/auth/change-password (POST) should fail password change with incorrect old password and not send email', async () => {
    const incorrectOldPassword = generatePassword();

    const result = await app.inject({
      method: 'POST',
      url: '/auth/change-password',
      payload: {
        oldPassword: incorrectOldPassword,
        newPassword: generatePassword(),
      },
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(result.statusCode).toBe(Errors.INVALID_PASSWORD.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(Errors.INVALID_PASSWORD.message);
  });

  it('/auth/change-password (POST) - should change the user password', async () => {
    const oldPassword = userPassword;
    const newPassword = generatePassword();

    const result = await app.inject({
      method: 'POST',
      url: '/auth/change-password',
      payload: {
        oldPassword: oldPassword,
        newPassword: newPassword,
      },
      cookies: {
        [CookieNames.ACCESS_TOKEN]: userAccessToken,
      },
    });

    expect(result.statusCode).toBe(201);

    const loginResult = await app.inject({
      method: 'POST',
      url: '/auth/sign',
      payload: {
        login: userEmail,
        password: newPassword,
      },
    });

    expect(loginResult.statusCode).toBe(200);

    expect(result.cookies).toBeDefined();

    const cookies = result.cookies;

    const accessToken = cookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    )?.value;
    const refreshToken = cookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    )?.value;

    expect(accessToken).toBeDefined();
    expect(refreshToken).toBeDefined();

    userAccessToken = accessToken!;
    userRefreshToken = refreshToken!;
  });

  it('/auth/lost-password/send-email (POST) - should send password reset email', async () => {
    const result = await app.inject({
      method: 'POST',
      url: '/auth/lost-password/send-email',
      payload: {
        email: userEmail,
      },
    });

    expect(result.statusCode).toBe(201);
    expect(mockTransporter.sendMail).toHaveBeenCalled();

    const mailOptions = sentMailOptions[sentMailOptions.length - 1];
    expect(mailOptions).toMatchObject({
      from: config.email.from,
      to: userEmail.toLowerCase(),
      subject: EmailTemplateSubjects['reset-password.mail'],
      template: EmailTemplatesEnum.RESET_PASSWORD,
      context: {
        appName: 'Helizium',
        username: expect.any(String),
        url: expect.any(String),
      },
    });
  });

  it('/auth/lost-password/verify (POST) - should return error for invalid token', async () => {
    const res = await userService.getIdAndUsernameByEmail(
      userEmail.toLowerCase(),
    );
    const userId = res?.id.toString('hex');

    const result = await app.inject({
      method: 'POST',
      url: '/auth/lost-password/verify',
      payload: { userId: userId, token: nanoid() },
    });

    expect(result.statusCode).toBe(Errors.INVALID_RESET_PASSWORD_TOKEN.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(
      Errors.INVALID_RESET_PASSWORD_TOKEN.message,
    );
  });

  it('/auth/lost-password/verify (POST) - should return 204 status code with valid token', async () => {
    const res = await userService.getIdAndUsernameByEmail(
      userEmail.toLowerCase(),
    );
    const userId = res?.id.toString('hex');

    const latestMailOptions = sentMailOptions[sentMailOptions.length - 1];
    const url = latestMailOptions.context.url;
    const parts = url.split('/');
    const token = parts[parts.length - 1];

    const result = await app.inject({
      method: 'POST',
      url: '/auth/lost-password/verify',
      payload: { userId: userId, token: token },
    });

    expect(result.statusCode).toBe(204);
  });

  it('/auth/lost-password/change (POST) - should return error for invalid token during password change', async () => {
    const res = await userService.getIdAndUsernameByEmail(
      userEmail.toLowerCase(),
    );
    const userId = res?.id.toString('hex');

    const result = await app.inject({
      method: 'POST',
      url: '/auth/lost-password/change',
      payload: {
        userId,
        token: nanoid(),
        password: generatePassword(),
      },
    });

    expect(result.statusCode).toBe(Errors.INVALID_RESET_PASSWORD_TOKEN.status);
    const payload = JSON.parse(result.payload);
    expect(payload.message).toContain(
      Errors.INVALID_RESET_PASSWORD_TOKEN.message,
    );
  });

  it('/auth/lost-password/change (POST) - should change password successfully', async () => {
    const res = await userService.getIdAndUsernameByEmail(
      userEmail.toLowerCase(),
    );
    const userId = res?.id.toString('hex');

    const latestMailOptions = sentMailOptions[sentMailOptions.length - 1];
    const url = latestMailOptions.context.url;
    const parts = url.split('/');
    const token = parts[parts.length - 1];

    const newPassword = generatePassword();

    const result = await app.inject({
      method: 'POST',
      url: '/auth/lost-password/change',
      payload: {
        userId,
        token: token,
        password: newPassword,
      },
    });

    expect(result.statusCode).toBe(201);

    const loginResult = await app.inject({
      method: 'POST',
      url: '/auth/sign',
      payload: {
        login: userEmail,
        password: newPassword,
      },
    });

    expect(loginResult.statusCode).toBe(200);

    expect(result.cookies).toBeDefined();

    const cookies = result.cookies;

    const accessToken = cookies.find(
      (cookie) => cookie.name === CookieNames.ACCESS_TOKEN,
    )?.value;
    const refreshToken = cookies.find(
      (cookie) => cookie.name === CookieNames.REFRESH_TOKEN,
    )?.value;

    expect(accessToken).toBeDefined();
    expect(refreshToken).toBeDefined();

    userAccessToken = accessToken!;
    userRefreshToken = refreshToken!;
  });

  afterEach(async () => {
    jest.clearAllMocks();
  });

  afterAll(async () => {
    await app.get('REDIS_CLIENT').quit();

    const dataSource = app.get(DataSource);
    if (dataSource.isInitialized) {
      await dataSource.destroy();
    }

    await app.close();
  });
});

import { faker } from '@faker-js/faker';
import { Test, TestingModule } from '@nestjs/testing';
import { DataSource } from 'typeorm';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { CookieNames, MfaMethods } from '../src/common/enums';
import {
  generateObjectId,
  generatePassword,
  generateUsername,
} from '../src/common/helpers';
import { USERS_PACKAGE_NAME } from '../src/modules/users';
import { AuthModule } from '../src/modules/auth';
import { APP_PIPE } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { databaseConfig } from '../src/config';
import { of } from 'rxjs';
import fastifyCookie from '@fastify/cookie';

describe('AuthController (e2e)', () => {
  let app: NestFastifyApplication;

  let userEmail: string;
  let userUsername: string;
  let userPassword: string;

  // TODO Use in e2e test
  let userAccessToken: string;
  let userRefreshToken: string;

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
      imports: [TypeOrmModule.forRoot(databaseConfig), AuthModule],
      providers: [
        {
          provide: APP_PIPE,
          useValue: new ValidationPipe({
            whitelist: true,
          }),
        },
      ],
    })
      .overrideProvider(USERS_PACKAGE_NAME)
      .useValue(mockClientGrpc)
      .compile();

    app = moduleRef.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );

    app.register(fastifyCookie);

    await app.init();
    await app.getHttpAdapter().getInstance().ready();
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

  // TODO try to logout

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

  // TODO try to terminate all sessions

  // TODO try to login with invalid password

  // TODO make others e2e test according to the example above

  afterAll(async () => {
    await app.get('REDIS_CLIENT').quit();

    const dataSource = app.get(DataSource);
    if (dataSource.isInitialized) {
      await dataSource.destroy();
    }

    await app.close();

    jest.clearAllMocks();
  });
});

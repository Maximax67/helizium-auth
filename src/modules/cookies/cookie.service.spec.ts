import { Test, TestingModule } from '@nestjs/testing';
import { CookieService } from './cookie.service';
import { FastifyReply, FastifyRequest } from 'fastify';
import { CookieSerializeOptions } from '@fastify/cookie';

describe('CookieService', () => {
  let cookieService: CookieService;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [CookieService],
    }).compile();

    cookieService = module.get<CookieService>(CookieService);
  });

  describe('CookieService', () => {
    it('should define set()', () => {
      expect(cookieService.set).toBeDefined();
      expect(typeof cookieService.set).toBe('function');
    });

    it('should define get()', () => {
      expect(cookieService.get).toBeDefined();
      expect(typeof cookieService.get).toBe('function');
    });

    it('should define delete()', () => {
      expect(cookieService.delete).toBeDefined();
      expect(typeof cookieService.delete).toBe('function');
    });
  });

  describe('set', () => {
    it('should set a cookie with the default options', () => {
      const res = {
        setCookie: jest.fn(),
      } as unknown as FastifyReply;

      const name = 'test-cookie';
      const value = 'test-value';

      cookieService.set(res, name, value);

      expect(res.setCookie).toHaveBeenCalledWith(
        name,
        value,
        expect.objectContaining({
          httpOnly: true,
          secure: false,
          sameSite: 'strict',
          path: '/',
        }),
      );
    });

    it('should set a cookie with custom options overriding defaults', () => {
      const res = {
        setCookie: jest.fn(),
      } as unknown as FastifyReply;

      const name = 'test-cookie';
      const value = 'test-value';
      const customOptions: CookieSerializeOptions = {
        path: '/custom',
        maxAge: 3600,
      };

      cookieService.set(res, name, value, customOptions);

      expect(res.setCookie).toHaveBeenCalledWith(
        name,
        value,
        expect.objectContaining({
          httpOnly: true,
          secure: false,
          sameSite: 'strict',
          path: '/custom',
          maxAge: 3600,
        }),
      );
    });
  });

  describe('get', () => {
    it('should return the cookie value if it exists', () => {
      const req = {
        cookies: {
          'test-cookie': 'test-value',
        },
      } as Partial<FastifyRequest>;

      const result = cookieService.get(req as FastifyRequest, 'test-cookie');
      expect(result).toBe('test-value');
    });

    it('should return null if the cookie does not exist', () => {
      const req = {
        cookies: {},
      } as FastifyRequest;

      const result = cookieService.get(req, 'non-existent-cookie');
      expect(result).toBeNull();
    });
  });

  describe('delete', () => {
    it('should delete a cookie with the default options', () => {
      const res = {
        clearCookie: jest.fn(),
      } as unknown as FastifyReply;

      const name = 'test-cookie';

      cookieService.delete(res, name);

      expect(res.clearCookie).toHaveBeenCalledWith(
        name,
        expect.objectContaining({
          httpOnly: true,
          secure: false,
          sameSite: 'strict',
          path: '/',
        }),
      );
    });

    it('should delete a cookie with custom options', () => {
      const res = {
        clearCookie: jest.fn(),
      } as unknown as FastifyReply;

      const name = 'test-cookie';
      const customOptions: CookieSerializeOptions = {
        path: '/custom',
        maxAge: 3600,
      };

      cookieService.delete(res, name, customOptions);

      expect(res.clearCookie).toHaveBeenCalledWith(
        name,
        expect.objectContaining({
          httpOnly: true,
          secure: false,
          sameSite: 'strict',
          path: '/custom',
          maxAge: 3600,
        }),
      );
    });
  });
});

import { Injectable } from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';
import { CookieSerializeOptions } from '@fastify/cookie';
import { NodeEnvTypes } from '../../common/enums';
import { config } from '../../config';

@Injectable()
export class CookieService {
  private readonly defaultOptions: CookieSerializeOptions = {
    httpOnly: true,
    secure: config.nodeEnv === NodeEnvTypes.PRODUCTION,
    sameSite: 'strict',
    path: '/',
  };

  public set(
    res: FastifyReply,
    name: string,
    value: string,
    options: CookieSerializeOptions = {},
  ): void {
    res.setCookie(name, value, { ...this.defaultOptions, ...options });
  }

  public get(req: FastifyRequest, name: string): string | null {
    return req.cookies[name] ?? null;
  }

  public delete(
    res: FastifyReply,
    name: string,
    options: CookieSerializeOptions = {},
  ): void {
    res.clearCookie(name, { ...this.defaultOptions, ...options });
  }
}

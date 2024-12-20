import { FastifyReply } from 'fastify';
import { TokenInfo } from './token-info.interface';

export interface AuthorizedRequest extends FastifyReply {
  auth: TokenInfo;
}

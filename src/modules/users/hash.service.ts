import * as bcrypt from 'bcrypt';
import { Injectable } from '@nestjs/common';
import { config } from '../../config';

@Injectable()
export class HashService {
  async hashData(data: string): Promise<string> {
    return bcrypt.hash(data, config.security.bcryptSaltRounds);
  }

  async compareHash(data: string, hash: string): Promise<boolean> {
    return bcrypt.compare(data, hash);
  }
}

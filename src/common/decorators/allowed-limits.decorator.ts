import { Reflector } from '@nestjs/core';
import { TokenLimits } from '../enums';

export const AllowedLimits = Reflector.createDecorator<
  TokenLimits | TokenLimits[]
>();

import { EmailCookieTokenStatuses } from '../enums';

export interface EmailTokenRedisValue {
  status: EmailCookieTokenStatuses;
  otp: string;
}

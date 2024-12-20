import { TokenInfo } from '../../../common/interfaces';
import { TokenRedisStatuses } from '../../../common/enums';

export interface TokenInfoWithStatus {
  decoded: TokenInfo;
  status: TokenRedisStatuses;
}

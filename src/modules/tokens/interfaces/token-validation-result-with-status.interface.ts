import { TokenInfo } from '../../../common/interfaces';
import { TokenRedisStatuses } from 'src/common/enums/token-redis-statuses.enum';

export interface TokenInfoWithStatus {
  decoded: TokenInfo;
  status: TokenRedisStatuses;
}

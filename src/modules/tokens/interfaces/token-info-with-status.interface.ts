import { TokenInfo } from '../../../common/interfaces';
import { TokenStatuses } from '../../../common/enums';

export interface TokenInfoWithStatus {
  decoded: TokenInfo;
  status: TokenStatuses;
}

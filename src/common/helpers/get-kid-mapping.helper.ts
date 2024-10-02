import { getJwks } from './get-jwks.hepler';
import { TokenTypes } from '../enums';

let cachedKidMapping: Record<TokenTypes, string> | null = null;

export async function getKidMapping(): Promise<Record<TokenTypes, string>> {
  if (!cachedKidMapping) {
    const jwks = await getJwks();
    cachedKidMapping = {
      [TokenTypes.ACCESS]: jwks[TokenTypes.ACCESS].kid,
      [TokenTypes.REFRESH]: jwks[TokenTypes.REFRESH].kid,
      [TokenTypes.API]: jwks[TokenTypes.API].kid,
    };
  }

  return cachedKidMapping;
}

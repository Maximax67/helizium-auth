import * as jose from 'node-jose';
import { Jwk } from '../interfaces';
import { TokenTypes } from '../enums';
import { config } from '../../config';

const generateJwk = async (
  pemKey: string,
  use: string,
  alg: string = 'RS256',
): Promise<Jwk> => {
  const key = await jose.JWK.asKey(pemKey, 'pem');
  const jwk: any = key.toJSON();
  return {
    kty: jwk.kty,
    use,
    n: jwk.n,
    e: jwk.e,
    kid: jwk.kid,
    x5t: jwk.x5t,
    x5c: jwk.x5c,
    alg,
  };
};

const generateJwks = async (): Promise<Record<TokenTypes, Jwk>> => {
  const { jwtAccessPublicKey, jwtRefreshPublicKey, jwtApiPublicKey } =
    config.keys;

  return {
    [TokenTypes.ACCESS]: await generateJwk(jwtAccessPublicKey, 'sig'),
    [TokenTypes.REFRESH]: await generateJwk(jwtRefreshPublicKey, 'sig'),
    [TokenTypes.API]: await generateJwk(jwtApiPublicKey, 'sig'),
  };
};

let cachedJwks: Record<TokenTypes, Jwk> | null = null;

export async function getJwks() {
  if (!cachedJwks) {
    cachedJwks = await generateJwks();
  }
  return cachedJwks;
}

export interface Jwk {
  kty: string;
  use: string;
  n: string;
  e: string;
  kid: string;
  x5t?: string;
  x5c?: string[];
  alg: string;
}

export function extractToken(
  token: string | undefined,
  prefix: string = 'Bearer',
): string | null {
  const prefixWithSpace = prefix + ' ';
  if (!token || !token.startsWith(prefixWithSpace)) {
    return null;
  }

  const encodedToken = token.substring(prefixWithSpace.length);

  return encodedToken.length ? encodedToken : null;
}

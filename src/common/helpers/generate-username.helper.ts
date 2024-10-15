const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';

export function generateUsername(): string {
  const length = Math.floor(Math.random() * (30 - 4 + 1)) + 4; // Random length between 4 and 30
  let username = '';

  username += chars[Math.floor(Math.random() * chars.length) - 1];

  for (let i = 1; i < length; i++) {
    username += chars[Math.floor(Math.random() * chars.length)];
  }

  return username;
}

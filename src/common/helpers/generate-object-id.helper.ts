const characters = '0123456789abcdef';

export function generateObjectId(): string {
  let result = '';

  for (let i = 0; i < 24; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    result += characters[randomIndex];
  }

  return result;
}

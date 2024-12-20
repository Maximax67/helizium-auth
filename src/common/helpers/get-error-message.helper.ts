export const getErrorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : 'An unknown error occurred';

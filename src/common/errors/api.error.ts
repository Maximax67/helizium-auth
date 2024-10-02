import { HttpException } from '@nestjs/common';
import { ApiErrorTemplate } from '../interfaces';

export class ApiError extends HttpException {
  private readonly errorId: string | null;

  constructor(template: ApiErrorTemplate) {
    const { message, status, id } = template;
    super(message, status);
    this.errorId = id ?? null;
    Object.setPrototypeOf(this, ApiError.prototype);
  }

  getErrorId(): string | null {
    return this.errorId;
  }
}

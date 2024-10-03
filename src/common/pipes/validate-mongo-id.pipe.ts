import {
  ArgumentMetadata,
  BadRequestException,
  Injectable,
  PipeTransform,
} from '@nestjs/common';

@Injectable()
export class ValidateMongoId implements PipeTransform<string> {
  transform(value: string, _metadata: ArgumentMetadata): string {
    if (/^[a-fA-F0-9]{24}$/.test(value)) {
      return value;
    }

    throw new BadRequestException();
  }
}

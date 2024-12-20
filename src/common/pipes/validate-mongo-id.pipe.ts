import {
  ArgumentMetadata,
  BadRequestException,
  Injectable,
  PipeTransform,
} from '@nestjs/common';
import { MONGOOSE_OBJECT_ID_REGEX } from '../constants';

@Injectable()
export class ValidateMongoId implements PipeTransform<string> {
  transform(value: string, _metadata: ArgumentMetadata): string {
    if (MONGOOSE_OBJECT_ID_REGEX.test(value)) {
      return value;
    }

    throw new BadRequestException();
  }
}

import { Expose } from 'class-transformer';

export class UriDto {
  @Expose()
  uri: string;
}

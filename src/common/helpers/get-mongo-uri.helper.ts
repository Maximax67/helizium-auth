import { Logger } from '@nestjs/common';
import { MongoMemoryServer } from 'mongodb-memory-server';

import { NodeEnvTypes } from '../enums';
import { config } from '../../config';

const { nodeEnv, mongodbUrl } = config;

export const getMongoUri = async (): Promise<string> => {
  if (nodeEnv === NodeEnvTypes.TEST) {
    return (await MongoMemoryServer.create()).getUri();
  }

  if (mongodbUrl) {
    return mongodbUrl;
  }

  new Logger('MongooseModule').warn(
    'MongoDb URI not set in env file. Using temporary MongoMemoryServer.',
  );

  return (await MongoMemoryServer.create()).getUri();
};

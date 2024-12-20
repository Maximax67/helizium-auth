import * as path from 'path';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { NodeEnvTypes } from '../common/enums';
import { config } from './config';

const nodeEnv = config.nodeEnv;

export const databaseConfig: TypeOrmModuleOptions = {
  type: 'postgres',
  url: config.databaseUrl,
  entities: [path.resolve(__dirname, '../**/*.entity.{t,j}s')],
  logging: nodeEnv === NodeEnvTypes.DEVELOPMENT,
  synchronize: nodeEnv !== NodeEnvTypes.PRODUCTION,
};

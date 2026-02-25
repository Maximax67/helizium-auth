import { DataSource } from 'typeorm';
import * as path from 'path';
import { config } from './config';
import { NodeEnvTypes } from '../common/enums';

const nodeEnv = config.nodeEnv;

export const AppDataSource = new DataSource({
  type: 'postgres',
  url: config.databaseUrl,
  entities: [path.resolve(__dirname, '../**/*.entity.{ts,js}')],
  migrations: [path.resolve(__dirname, '../migrations/*.{ts,js}')],
  logging: nodeEnv === NodeEnvTypes.DEVELOPMENT,
  synchronize: false,
});

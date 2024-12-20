import { Test, TestingModule } from '@nestjs/testing';
import { AppService } from './app.service';
import { NodeEnvTypes } from './common/enums';

describe('AppService', () => {
  let appService: AppService;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AppService],
    }).compile();

    appService = module.get<AppService>(AppService);
  });

  it('should be defined', () => {
    expect(appService).toBeDefined();
  });

  it('should define getApiInfo()', () => {
    expect(appService.getApiInfo).toBeDefined();
    expect(typeof appService.getApiInfo).toBe('function');
  });

  it('should return correct API info', () => {
    const apiInfo = appService.getApiInfo();

    expect(apiInfo).toBeInstanceOf(Object);

    expect(typeof apiInfo.environment).toBe('string');
    expect(apiInfo.environment).toBe(NodeEnvTypes.TEST);

    expect(typeof apiInfo.title).toBe('string');
    expect(typeof apiInfo.version).toBe('string');
  });
});

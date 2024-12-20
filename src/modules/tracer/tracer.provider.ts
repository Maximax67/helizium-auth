import { DynamicModule, Module } from '@nestjs/common';
import { trace } from '@opentelemetry/api';
import { TRACER_NAME } from './tracer.module';

@Module({})
export class TracerProviderModule {
  static register(): DynamicModule {
    return {
      module: TracerProviderModule,
      providers: [
        {
          provide: 'TRACER',
          useValue: trace.getTracer(TRACER_NAME),
        },
      ],
      exports: ['TRACER'],
    };
  }
}

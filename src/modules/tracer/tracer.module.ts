import { Module, Global } from '@nestjs/common';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { NestInstrumentation } from '@opentelemetry/instrumentation-nestjs-core';
import { PgInstrumentation } from '@opentelemetry/instrumentation-pg';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME } from '@opentelemetry/semantic-conventions';
import { config } from '../../config';

export const TRACER_NAME = config.title;

@Global()
@Module({})
export class TracerModule {
  static initialize() {
    if (!config.otlpCollectorUrl) {
      return;
    }

    const otlpExporter = new OTLPTraceExporter({
      url: config.otlpCollectorUrl,
    });

    const sdk = new NodeSDK({
      resource: resourceFromAttributes({
        [ATTR_SERVICE_NAME]: TRACER_NAME,
      }),
      spanProcessor: new SimpleSpanProcessor(otlpExporter) as any,
      instrumentations: [
        new HttpInstrumentation(),
        new NestInstrumentation(),
        new PgInstrumentation(),
      ],
    });

    sdk.start();
  }
}

import { Module, Global } from '@nestjs/common';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { FastifyInstrumentation } from '@opentelemetry/instrumentation-fastify';
import { NestInstrumentation } from '@opentelemetry/instrumentation-nestjs-core';
import { PgInstrumentation } from '@opentelemetry/instrumentation-pg';
import { Resource } from '@opentelemetry/resources';
import { config } from '../../config';

export const TRACER_NAME = config.title;

@Global()
@Module({})
export class TracerModule {
  static initialize() {
    const otlpExporter = new OTLPTraceExporter({
      url: config.otlpCollectorUrl,
    });

    const sdk = new NodeSDK({
      resource: new Resource({
        'service.name': TRACER_NAME,
      }),
      spanProcessor: new SimpleSpanProcessor(otlpExporter),
      instrumentations: [
        new HttpInstrumentation(),
        new FastifyInstrumentation(),
        new NestInstrumentation(),
        new PgInstrumentation(),
      ],
    });

    sdk.start();
  }
}

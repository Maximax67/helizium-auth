import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';
import { generateErrorId, objectToString } from '../helpers';
import { ApiError } from '../errors';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest<FastifyRequest>();
    const response = ctx.getResponse<FastifyReply>();
    const { method, url, query, params, body } = request;
    const timestamp = new Date().toISOString();
    const loggedRecordId = generateErrorId();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const message =
      exception instanceof HttpException
        ? exception.message
        : 'Internal Server Error';

    const errorTemplateId =
      exception instanceof ApiError ? exception.getErrorId() : null;

    const stack = exception instanceof Error ? exception.stack : undefined;
    let toSend: object = {
      statusCode: status,
      timestamp,
      type: errorTemplateId ?? undefined,
      loggedRecordId,
    };

    if (exception instanceof HttpException) {
      const defaultResponce = exception.getResponse();
      toSend = {
        ...toSend,
        ...(defaultResponce instanceof Object
          ? defaultResponce
          : { error: defaultResponce }),
      };
    } else {
      toSend = {
        ...toSend,
        message: exception instanceof Error ? exception.message : undefined,
        error: 'Internal Server Error',
      };
    }

    const loggerHeader = `${loggedRecordId}: ${errorTemplateId ?? message}`;
    const paramsString = objectToString(params);
    const queryString = objectToString(query);
    const responseString = objectToString(toSend);

    let debugMessage =
      loggerHeader +
      `\n${method}: ${url}\n` +
      `Params: ${paramsString};\n` +
      `Query: ${queryString};\n`;

    if (method !== 'GET') {
      if (body && typeof body === 'object' && 'password' in body) {
        body.password = '<hidden>';
      }

      debugMessage += `Body: ${objectToString(body)};\n`;
    }

    debugMessage += `Response: ${responseString}`;

    this.logger.error(loggerHeader, stack);
    this.logger.debug(debugMessage);

    response.status(status).send(toSend);
  }
}

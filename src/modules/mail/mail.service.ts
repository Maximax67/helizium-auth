import * as nodemailer from 'nodemailer';
import { Inject, Injectable } from '@nestjs/common';
import {
  EmailTemplateContexts,
  EmailTemplateSubjects,
} from './interfaces/email-template.interface';
import { config } from '../../config';
import { SpanStatusCode, Tracer } from '@opentelemetry/api';
import { getErrorMessage } from '../../common/helpers';

@Injectable()
export class MailService {
  private readonly transporter: nodemailer.Transporter;

  constructor(
    @Inject('NODEMAIL_TRANSPORTER') transporter: nodemailer.Transporter,
    @Inject('TRACER') private readonly tracer: Tracer,
  ) {
    this.transporter = transporter;
  }

  async sendMail<T extends keyof typeof EmailTemplateSubjects>(
    to: string,
    template: T,
    context: Extract<EmailTemplateContexts, { template: T }>['context'],
  ): Promise<void> {
    const subject = EmailTemplateSubjects[template];
    const mailOptions = {
      from: config.email.from,
      to,
      subject,
      template,
      context,
    };

    const span = this.tracer.startSpan('mail:send');
    try {
      await this.transporter.sendMail(mailOptions);
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: getErrorMessage(error),
      });

      throw error;
    } finally {
      span.end();
    }
  }
}

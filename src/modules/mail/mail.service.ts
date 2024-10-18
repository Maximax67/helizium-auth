import * as nodemailer from 'nodemailer';
import { Inject, Injectable } from '@nestjs/common';
import {
  EmailTemplateContexts,
  EmailTemplateSubjects,
} from './interfaces/email-template.interface';
import { config } from '../../config';

@Injectable()
export class MailService {
  private readonly transporter: nodemailer.Transporter;

  constructor(
    @Inject('NODEMAIL_TRANSPORTER') transporter: nodemailer.Transporter,
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

    try {
      await this.transporter.sendMail(mailOptions);
    } catch (error) {
      throw error;
    }
  }
}

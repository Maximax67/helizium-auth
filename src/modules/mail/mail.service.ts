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

  // TODO Add unit tests
  //^ Ensure send options are valid
  //^ Ensure sendMail method is called for nodemailer transporter
  async sendMail<T extends keyof EmailTemplateContexts>(
    to: string,
    template: T,
    context: EmailTemplateContexts[T],
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
      console.log(`Email sent to ${to}`);
    } catch (error) {
      console.error(`Error sending email to ${to}`);
      throw error;
    }
  }
}

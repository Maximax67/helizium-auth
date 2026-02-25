import * as nodemailer from 'nodemailer';
import * as hbs from 'nodemailer-express-handlebars';
import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { config } from '../../config';
import { TracerProviderModule } from '../tracer';

@Module({
  imports: [TracerProviderModule.register()],
  providers: [
    MailService,
    {
      provide: 'NODEMAIL_TRANSPORTER',
      useFactory: () => {
        const { host, port, user, password } = config.email;
        return nodemailer
          .createTransport({
            host,
            port,
            secure: port === 465,
            auth: {
              user,
              pass: password,
            },
          })
          .use(
            'compile',
            hbs({
              viewEngine: {
                partialsDir: './src/modules/mail/mails',
                defaultLayout: false,
              },
              viewPath: './src/modules/mail/mails',
            }),
          );
      },
    },
  ],
  exports: [MailService],
})
export class MailModule {}

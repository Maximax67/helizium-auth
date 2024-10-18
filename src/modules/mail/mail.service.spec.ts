import { Test, TestingModule } from '@nestjs/testing';
import { MailService } from './mail.service';
import { config } from '../../config';
import { EmailTemplateSubjects } from './interfaces/email-template.interface';
import { EmailTemplatesEnum } from '../../common/enums';

const mockTransporter = {
  sendMail: jest.fn(),
};

describe('MailService', () => {
  let mailService: MailService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MailService,
        {
          provide: 'NODEMAIL_TRANSPORTER',
          useValue: mockTransporter,
        },
      ],
    }).compile();

    mailService = module.get<MailService>(MailService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should call transporter.sendMail with correct options', async () => {
    const to = 'test@example.com';
    const template = EmailTemplatesEnum.CONFIRM_EMAIL;
    const context = {
      appName: 'TestApp',
      otp: '123456',
      username: 'testuser',
      url: 'https://example.com',
    };

    const expectedMailOptions = {
      from: config.email.from,
      to,
      subject: EmailTemplateSubjects[template],
      template,
      context,
    };

    await mailService.sendMail(to, template, context);

    expect(mockTransporter.sendMail).toHaveBeenCalledWith(expectedMailOptions);
  });

  it('should throw an error and log failure message if sending email fails', async () => {
    const errorMessage = 'Failed to send email';
    mockTransporter.sendMail.mockRejectedValueOnce(new Error(errorMessage));

    const to = 'test@example.com';
    const template = EmailTemplatesEnum.CONFIRM_EMAIL;
    const context = {
      appName: 'TestApp',
      otp: '123456',
      username: 'testuser',
      url: 'https://example.com',
    };

    await expect(mailService.sendMail(to, template, context)).rejects.toThrow(
      errorMessage,
    );
  });
});

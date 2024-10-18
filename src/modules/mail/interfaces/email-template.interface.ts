import { APP_NAME } from '../../../common/constants';
import { EmailTemplatesEnum } from '../../../common/enums';

interface EmailTemplateOtpContext {
  appName: string;
  otp: string;
  username: string;
  url: string;
}

interface EmailTemplateResetPasswordContext {
  appName: string;
  username: string;
  url: string;
}

export type EmailTemplateContexts =
  | {
      template: EmailTemplatesEnum.CONFIRM_EMAIL;
      context: EmailTemplateOtpContext;
    }
  | { template: EmailTemplatesEnum.MFA_EMAIL; context: EmailTemplateOtpContext }
  | {
      template: EmailTemplatesEnum.RESET_PASSWORD;
      context: EmailTemplateResetPasswordContext;
    };

export const EmailTemplateSubjects: Record<EmailTemplatesEnum, string> = {
  [EmailTemplatesEnum.CONFIRM_EMAIL]: `Confirm email for ${APP_NAME}`,
  [EmailTemplatesEnum.MFA_EMAIL]: `Confirm OTP for ${APP_NAME}`,
  [EmailTemplatesEnum.RESET_PASSWORD]: `Password reset request for ${APP_NAME}`,
};

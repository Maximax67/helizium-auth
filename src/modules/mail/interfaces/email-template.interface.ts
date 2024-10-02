import { APP_NAME } from '../../../common/constants';
import { EmailTemplatesEnum } from '../../../common/enums';

interface EmailTemplateContext {
  appName: string;
  otp: string;
  username: string;
  url: string;
}

export type EmailTemplateContexts = {
  [EmailTemplatesEnum.CONFIRM_EMAIL]: EmailTemplateContext;
  [EmailTemplatesEnum.MFA_EMAIL]: EmailTemplateContext;
};

export const EmailTemplateSubjects: Record<EmailTemplatesEnum, string> = {
  [EmailTemplatesEnum.CONFIRM_EMAIL]: `Confirm email for ${APP_NAME}`,
  [EmailTemplatesEnum.MFA_EMAIL]: `Confirm OTP for ${APP_NAME}`,
};

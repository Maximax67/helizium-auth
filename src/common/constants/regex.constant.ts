export const MONGOOSE_OBJECT_ID_REGEX = /^[a-f0-9]{24}$/;

export const USERNAME_REGEX = /^(?=.*[a-zA-Z])[a-zA-Z0-9_]{4,30}$/;
export const EMAIL_REGEX = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;
export const PASSWORD_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d!@#$%^&*()_+[\]{}|;:'",.<>?\/\\-]{8,32}$/;
export const LOGIN_REGEX =
  /^(?=.{4,254}$)((?=.*[a-zA-Z])[a-zA-Z0-9_]{4,30}|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$/;

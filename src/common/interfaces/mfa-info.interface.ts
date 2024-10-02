import { MfaMethods } from '../enums';

export interface MfaInfo {
  required: boolean;
  methods: MfaMethods[];
}

import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Model, Types } from 'mongoose';
import { User } from '../../users/schemas';
import { config } from '../../../config';

@Schema()
export class ApiToken {
  @Prop({ required: true, ref: User.name })
  userId: Types.ObjectId;

  @Prop({ required: true })
  jti: string;

  @Prop({ required: true })
  title: string;

  @Prop({ default: false })
  writeAccess: boolean;
}

export type ApiTokenDocument = HydratedDocument<ApiToken>;

const ApiTokenSchema = SchemaFactory.createForClass(ApiToken);

ApiTokenSchema.pre('save', async function (next) {
  try {
    const Model = this.constructor as Model<ApiTokenDocument>;
    const tokenCount = await Model.countDocuments({ userId: this.userId });

    if (tokenCount >= config.security.apiTokensLimitPerUser) {
      const error = new Error('max api tokens');
      return next(error);
    }

    next();
  } catch (err) {
    next(err as Error);
  }
});

ApiTokenSchema.index({ userId: 1 });

export { ApiTokenSchema };

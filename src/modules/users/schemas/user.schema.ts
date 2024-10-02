import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';
import { Badges, UsernameColors, PremiumSubscriptions } from '../enums';

@Schema({
  timestamps: true,
  toObject: { virtuals: true },
  toJSON: { virtuals: true },
})
export class User {
  @Prop({ trim: true, required: true, unique: true })
  username: string;

  @Prop({ trim: true, required: true, unique: true })
  email: string;

  @Prop({ default: false })
  isEmailConfirmed: boolean;

  @Prop({ default: false })
  isBanned: boolean;

  @Prop({ required: true })
  passwordHash: string;

  @Prop({ default: false })
  mfaRequired: boolean;

  @Prop()
  totpSecret?: string;

  @Prop()
  avatar?: string;

  @Prop({ min: 0, default: 0 })
  balance: number;

  @Prop({ min: 0, max: 100, default: 0 })
  trustRate: number;

  @Prop({ default: [] })
  badges: Types.DocumentArray<Badge>;

  @Prop({ default: [] })
  usernameColors: Types.DocumentArray<UsernameColor>;

  @Prop({ enum: Object.keys(PremiumSubscriptions) })
  premiumStatus?: string;

  selectedUsernameColor: UsernameColors;

  pinnedBadge: Badge;
}

@Schema()
export class Badge {
  @Prop({ type: Types.ObjectId, ref: User.name, required: true })
  addedBy: Types.ObjectId;

  @Prop({ type: String, enum: Object.values(Badges), required: true })
  badge: string;

  @Prop({ type: Boolean, default: false })
  pinned: boolean;

  @Prop({ type: Types.ObjectId, ref: User.name })
  removedBy?: Types.ObjectId;

  @Prop({ type: Date })
  removedTimestamp?: Date;
}

@Schema()
export class UsernameColor {
  @Prop({ type: Types.ObjectId, ref: User.name, required: true })
  addedBy: Types.ObjectId;

  @Prop({ type: String, enum: Object.values(UsernameColors), required: true })
  color: string;

  @Prop({ type: Boolean, default: false })
  selected: boolean;

  @Prop({ type: Types.ObjectId, ref: User.name })
  removedBy?: Types.ObjectId;

  @Prop({ type: Date })
  removedTimestamp?: Date;
}

export type UserDocument = HydratedDocument<User>;

const UserSchema = SchemaFactory.createForClass(User);

UserSchema.virtual('selectedUsernameColor').get(function () {
  return (
    this.usernameColors.find(
      ({ selected, removedBy }) => selected && !removedBy,
    )?.color ?? UsernameColors.DEFAULT
  );
});

UserSchema.virtual('pinnedBadge').get(function () {
  return this.badges.find((badge) => badge.pinned && !badge.removedBy) ?? null;
});

UserSchema.index({ username: 1 });
UserSchema.index({ email: 1 });

export { UserSchema };

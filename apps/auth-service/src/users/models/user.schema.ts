import { Exclude } from "class-transformer";
import { AbstractDocument } from "@app/common";
import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

export type UserType = 'member' | 'staff' | 'admin';

@Schema({ versionKey: false, timestamps: true })
export class User extends AbstractDocument {
  @Prop({ required: true })
  firstName: string;

  @Prop({ required: true })
  lastName: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  @Exclude()
  passwordHash: string;

  @Prop({ default: null })
  resetOtp?: string;

  @Prop({ default: null })
  resetOtpExpires?: Date;

  @Prop({ required: true, unique: true })
  phone: string;

  @Prop({ required: false })
  avatarUrl?: string;

  @Prop({ required: true, enum: ['member', 'staff', 'admin'] })
  type?: UserType;

  @Prop({ default: false })
  isEmailVerified: boolean;

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ default: null })
  lastLoginAt: string;

  @Prop({ required: false })
  otpRequestCount?: number;

  @Prop({ required: false })
  otpRequestWindowStart?: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);

// UserSchema.index({ email: 1 });

export interface UserR {
  status: number;
  message?: string;
  data?: boolean | User | User[];
}
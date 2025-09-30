import { AbstractDocument } from "@app/common";
import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

@Schema({ versionKey: false, timestamps: true })
export class LoginActivity extends AbstractDocument {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true, enum: ['success', 'failed'] })
  status: 'success' | 'failed';

  @Prop()
  ipAddress?: string;

  @Prop()
  userAgent?: string;

  @Prop({ type: Object })
  location?: {
    country?: string;
    city?: string;
    region?: string;
  };

  @Prop({ type: Object })
  device?: {
    browser?: string;
    os?: string;
    type?: string; // mobile, tablet, desktop, etc.
  };

  @Prop()
  isNewLocation?: boolean;

  @Prop()
  reason?: string; // e.g. "Wrong password", "Account locked", "MFA failed"

  @Prop({ default: false })
  isSuspicious?: boolean; // flagged by anomaly detection

  @Prop({ default: Date.now })
  loginAt?: Date; // explicit login timestamp
}

export const LoginActivitySchema = SchemaFactory.createForClass(LoginActivity);

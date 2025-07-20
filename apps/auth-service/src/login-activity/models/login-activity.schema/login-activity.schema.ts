import { AbstractDocument } from "@app/common";
import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

@Schema({ versionKey: false, timestamps: true })
export class LoginActivity extends AbstractDocument {
  @Prop({ required: true })
  userId: string;

  @Prop()
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

  @Prop()
  isNewLocation?: boolean;

  @Prop()
  reason?: string;
}

export const LoginActivitySchema = SchemaFactory.createForClass(LoginActivity);

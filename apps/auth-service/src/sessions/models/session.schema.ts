import { AbstractDocument } from '@app/common';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

@Schema({ timestamps: true })
export class Session extends AbstractDocument {
  @Prop({ required: true })
  userId: string;

  // @Prop() deviceName: string;

  @Prop({ type: Object })
  deviceName?: {
    browser?: string;
    os?: string;
    type?: string; // mobile, tablet, desktop, etc.
  };

  @Prop({ required: true })
  ipAddress: string;

  @Prop() userAgent: string;

  @Prop({ type: String, default: null }) currentRefreshHash?: string | null;

  // @Prop() location?: string;

  @Prop({ type: Object })
  location?: {
    country?: string;
    city?: string;
    region?: string;
  };

  @Prop({ default: false }) isCurrentDevice: boolean;

  @Prop({ default: false }) isSuspicious: boolean;

  @Prop({ default: false }) revoked: boolean;

  @Prop({ default: Date.now }) lastSeenAt: Date;
}

export const SessionSchema = SchemaFactory.createForClass(Session);
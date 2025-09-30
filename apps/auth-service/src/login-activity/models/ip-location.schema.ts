// ip-location.entity.ts
import { AbstractDocument } from '@app/common';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

@Schema({ timestamps: true })
export class IpLocation extends AbstractDocument {
  @Prop({ required: true, unique: true })
  ip: string;

  @Prop()
  country?: string;

  @Prop()
  city?: string;

  @Prop()
  region?: string;
}

export const IpLocationSchema = SchemaFactory.createForClass(IpLocation);

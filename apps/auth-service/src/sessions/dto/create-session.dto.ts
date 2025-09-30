import { IsBoolean, IsDate, IsObject, IsOptional, IsString } from "class-validator";

export class CreateSessionDto {
  @IsString()
  userId: string;

  @IsString()
  ipAddress?: string;

  @IsString()
  @IsOptional()
  userAgent?: string;

  @IsObject()
  @IsOptional()
  location?: {
    country?: string;
    city?: string;
    region?: string;
  };

  @IsObject()
  @IsOptional()
  deviceName?: {
    browser?: string;
    os?: string;
    type?: string;
  };

  // @IsString()
  // @IsOptional()
  // location?: string;

  @IsBoolean()
  @IsOptional()
  isCurrentDevice?: boolean;

  @IsDate()
  @IsOptional()
  lastSeenAt?: Date;
}
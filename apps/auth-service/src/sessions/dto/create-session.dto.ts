import { IsBoolean, IsDate, IsOptional, IsString } from "class-validator";

export class CreateSessionDto {
  @IsString()
  userId: string;

  @IsString()
  ipAddress?: string;

  @IsString()
  @IsOptional()
  userAgent?: string;

  @IsString()
  @IsOptional()
  deviceName?: string;

  @IsString()
  @IsOptional()
  location?: string;

  @IsBoolean()
  @IsOptional()
  isCurrentDevice?: boolean;

  @IsDate()
  @IsOptional()
  lastSeenAt?: Date;
}
import { IsBoolean, IsDate, IsOptional, IsString } from "class-validator";

export class UpdateSessionDto {
  @IsBoolean()
  @IsOptional()
  isSuspicious?: boolean;

  @IsBoolean()
  @IsOptional()
  revoked?: boolean;

  @IsString()
  @IsOptional()
  currentRefreshHash?: string;

  @IsDate()
  @IsOptional()
  lastSeenAt?: Date;
}
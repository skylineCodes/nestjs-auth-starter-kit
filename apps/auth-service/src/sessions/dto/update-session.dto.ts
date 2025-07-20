import { IsBoolean, IsDate, IsOptional, IsString } from "class-validator";

export class UpdateSessionDto {
  @IsBoolean()
  @IsOptional()
  isSuspicious?: boolean;

  @IsBoolean()
  @IsOptional()
  revoked?: boolean;

  @IsDate()
  @IsOptional()
  lastSeenAt?: Date;
}
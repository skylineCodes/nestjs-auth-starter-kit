import { IsEnum, IsOptional, IsString } from "class-validator";
import { UserType } from "../models/user.schema";


export class UpdateUserDto {
  @IsOptional()
  @IsString()
  firstName?: string;
  
  @IsOptional()
  @IsString()
  lastName?: string;

  @IsOptional()
  @IsString()
  phone?: string;

  @IsOptional()
  @IsString()
  passwordHash?: string;

  @IsOptional()
  resetOtp?: string | null;

  @IsOptional()
  resetOtpExpires?: string | null;

  @IsOptional()
  otpRequestCount?: number | null;

  @IsOptional()
  otpRequestWindowStart?: string | null;

  @IsOptional()
  @IsString()
  avatarUrl?: string;

  @IsOptional()
  @IsEnum(["member", "staff", "admin"])
  type?: UserType;
}
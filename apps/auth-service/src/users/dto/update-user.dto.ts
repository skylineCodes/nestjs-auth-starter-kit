import { IsEnum, IsOptional, IsString } from "class-validator";
import { UserType } from "../models/user.schema";
import { ApiProperty } from "@nestjs/swagger";


export class UpdateUserDto {
  @ApiProperty({ example: "John" })
  @IsOptional()
  @IsString()
  firstName?: string;
  
  @ApiProperty({ example: "Doe" })
  @IsOptional()
  @IsString()
  lastName?: string;

  @ApiProperty({ example: "(212) 555-0123" })
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
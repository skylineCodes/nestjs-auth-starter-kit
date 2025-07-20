import { IsBoolean, IsDate, IsDateString, IsEmail, IsNotEmpty, IsOptional, IsString, IsStrongPassword } from "class-validator";

export class CreateUserDto {
  @IsString()
  firstName: string;

  @IsString()
  lastName: string;

  @IsEmail()
  email: string;

  @IsStrongPassword()
  password: string;

  @IsString()
  phone: string;
  
  @IsOptional()
  @IsString()
  resetOtp: string | null = null;

  @IsOptional()
  @IsDateString()
  resetOtpExpires: string | null = null;

  @IsOptional()
  @IsDateString()
  otpRequestWindowStart: string | null = null;

  @IsNotEmpty()
  type: string = 'member';

  @IsBoolean()
  isEmailVerified: boolean = false;

  @IsOptional()
  @IsBoolean()
  isActive: boolean = true;

  @IsOptional()
  @IsString()
  lastLoginAt: string | null = null;
}
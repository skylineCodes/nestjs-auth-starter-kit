import { ApiProperty } from "@nestjs/swagger";
import { IsBoolean, IsDate, IsDateString, IsEmail, IsNotEmpty, IsOptional, IsString, IsStrongPassword } from "class-validator";

export class CreateUserDto {
  @ApiProperty({ example: "John" })
  @IsString()
  firstName: string;

  @ApiProperty({ example: "Doe" })
  @IsString()
  lastName: string;

  @ApiProperty({ example: "johndoe@gmail.com" })
  @IsEmail()
  email: string;

  @ApiProperty({ example: "*******" })
  @IsStrongPassword()
  password: string;

  @ApiProperty({ example: "(212) 555-0123" })
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
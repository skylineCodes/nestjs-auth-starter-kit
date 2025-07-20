import { IsNotEmpty, IsString } from 'class-validator';

export class ResetPasswordDto {
  @IsString()
  otp: string;

  @IsString()
  @IsNotEmpty()
  newPassword: string;
}
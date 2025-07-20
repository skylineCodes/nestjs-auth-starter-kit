import { IsString } from 'class-validator';

export class ResendResetPasswordDto {
  @IsString()
  email: string;
}
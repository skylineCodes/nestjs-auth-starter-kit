import { IsEmail, IsOptional, IsString } from "class-validator";

export class NotifyEmailDTO {
  @IsEmail()
  email: string;

  @IsString()
  subject: string;

  @IsString()
  @IsOptional()
  text?: string;

  @IsOptional()
  html?: any;

  @IsOptional()
  attachments?: any;
}
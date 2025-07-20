import { IsBoolean, IsOptional, IsString } from 'class-validator';

export class LogoutDto {
  @IsString()
  @IsOptional()
  userId?: string;
  
  @IsString()
  @IsOptional()
  sessionId: string;

  @IsBoolean()
  logoutAll: boolean;
}
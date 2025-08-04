import { IsBoolean, IsEmpty, IsOptional, IsString } from 'class-validator';

export class LogoutDto {
  @IsString()
  @IsOptional()
  userId?: string;
  
  @IsString()
  @IsOptional()
  sessionId?: string | null;

  @IsBoolean()
  logoutAll: boolean;
}
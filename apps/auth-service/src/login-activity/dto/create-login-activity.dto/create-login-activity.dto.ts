import { IsBoolean, IsObject, IsOptional, IsString } from "class-validator";


export class CreateLoginActivityDto {
  @IsString()
  userId: string;
  
  @IsString()
  status: 'success' | 'failed';

  @IsString()
  @IsOptional()
  ipAddress?: string;

  @IsString()
  @IsOptional()
  userAgent?: string;

  @IsObject()
  location?: {
    country?: string;
    city?: string;
    region?: string;
  }

  @IsBoolean()
  @IsOptional()
  isNewLocation?: boolean | null;

  @IsString()
  @IsOptional()
  reason?: string;
}

import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsDateString,
  IsObject,
  IsOptional,
  IsString,
} from 'class-validator';

export class CreateLoginActivityDto {
  @ApiProperty({
    example: '68d6cba801ca23646d9a94ae',
    description: 'ID of the user (may be null for failed attempts)',
  })
  @IsString()
  @IsOptional()
  userId?: string;

  @ApiProperty({ example: 'success', description: 'Login status' })
  @IsString()
  status: 'success' | 'failed';

  @ApiProperty({
    example: '::ffff:172.19.0.8',
    description: 'IP address from which login was attempted',
  })
  @IsString()
  @IsOptional()
  ipAddress?: any;

  @ApiProperty({
    example: 'PostmanRuntime/7.44.0',
    description: 'User agent string of the device/browser',
  })
  @IsString()
  @IsOptional()
  userAgent?: string;

  @ApiProperty({
    example: { country: 'Nigeria', city: 'Lagos', region: 'Lagos' },
    description: 'Geo-location info of login attempt',
  })
  @IsObject()
  @IsOptional()
  location?: {
    country?: string;
    city?: string;
    region?: string;
  };

  @ApiProperty({
    example: { browser: 'Chrome', os: 'Windows', type: 'desktop' },
    description: 'Device information extracted from user-agent',
  })
  @IsObject()
  @IsOptional()
  device?: {
    browser?: string;
    os?: string;
    type?: string;
  };

  @ApiProperty({
    example: true,
    description: 'Whether login happened from a new location',
  })
  @IsBoolean()
  @IsOptional()
  isNewLocation?: boolean | null;

  @ApiProperty({
    example: 'Invalid password',
    description: 'Reason for failed login, or anomaly flag',
  })
  @IsString()
  @IsOptional()
  reason?: string;

  @ApiProperty({
    example: true,
    description: 'Marks if login is considered suspicious (e.g. unusual location/device)',
  })
  @IsBoolean()
  @IsOptional()
  isSuspicious?: boolean;
}

export class LoginHistoryResponseDto {
  @ApiProperty({ example: 200 })
  status: number;

  @ApiProperty({ type: [CreateLoginActivityDto] })
  data: CreateLoginActivityDto[];
}

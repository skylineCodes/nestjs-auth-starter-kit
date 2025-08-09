import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsObject, IsOptional, IsString } from "class-validator";


export class CreateLoginActivityDto {
  // @ApiProperty() _id: string;

  @ApiProperty()
  @IsString()
  userId: string;
  
  @ApiProperty({ example: 'success', description: 'Login status' })
  @IsString()
  status: 'success' | 'failed';

  @ApiProperty({
    example: '::ffff:172.19.0.8',
    description: 'IP address from which login was attempted',
  })
  @IsString()
  @IsOptional()
  ipAddress?: string;

  @ApiProperty({
    example: 'PostmanRuntime/7.44.0',
    description: 'User agent string of the device/browser',
  })
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

  // @ApiProperty({
  //   example: '2025-08-03T15:16:57.979Z',
  //   description: 'Record creation timestamp',
  // })
  // createdAt: string;

  // @ApiProperty({
  //   example: '2025-08-03T15:16:57.979Z',
  //   description: 'Record update timestamp',
  // })
  // updatedAt: string;
}

export class LoginHistoryResponseDto {
  @ApiProperty({ example: 200 })
  status: number;

  @ApiProperty({ type: [CreateLoginActivityDto] })
  data: CreateLoginActivityDto[];
}

import { Module } from '@nestjs/common';
import { DtoService } from './dto.service';

@Module({
  providers: [DtoService],
  exports: [DtoService],
})
export class DtoModule {}

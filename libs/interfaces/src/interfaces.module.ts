import { Module } from '@nestjs/common';
import { InterfacesService } from './interfaces.service';

@Module({
  providers: [InterfacesService],
  exports: [InterfacesService],
})
export class InterfacesModule {}

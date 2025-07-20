import { Test, TestingModule } from '@nestjs/testing';
import { InterfacesService } from './interfaces.service';

describe('InterfacesService', () => {
  let service: InterfacesService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [InterfacesService],
    }).compile();

    service = module.get<InterfacesService>(InterfacesService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});

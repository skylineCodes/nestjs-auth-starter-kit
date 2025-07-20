import { Test, TestingModule } from '@nestjs/testing';
import { DtoService } from './dto.service';

describe('DtoService', () => {
  let service: DtoService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [DtoService],
    }).compile();

    service = module.get<DtoService>(DtoService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});

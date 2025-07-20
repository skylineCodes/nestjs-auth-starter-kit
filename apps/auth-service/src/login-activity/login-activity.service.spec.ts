import { Test, TestingModule } from '@nestjs/testing';
import { LoginActivityService } from './login-activity.service';

describe('LoginActivityService', () => {
  let service: LoginActivityService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [LoginActivityService],
    }).compile();

    service = module.get<LoginActivityService>(LoginActivityService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});

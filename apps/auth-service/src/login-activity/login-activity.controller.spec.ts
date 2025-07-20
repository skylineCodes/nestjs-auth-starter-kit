import { Test, TestingModule } from '@nestjs/testing';
import { LoginActivityController } from './login-activity.controller';

describe('LoginActivityController', () => {
  let controller: LoginActivityController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [LoginActivityController],
    }).compile();

    controller = module.get<LoginActivityController>(LoginActivityController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});

import { Body, Controller, Post, Res } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UsersService } from './users.service';
import { Response } from 'express';
import { UserR } from './models/user.schema';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // @Post()
  // async createUser(@Body() createUserDto: CreateUserDto, @Res() response: Response) {
  //   const userResponse: UserR = await this.usersService.create(createUserDto, response);

  //   return response.status(userResponse?.status).json(userResponse);
  // }
}

import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty } from "class-validator";


export class LoginUserDto {

  @ApiProperty({ example: "johndoe@gmail.com" })
  @IsEmail()
  email: string;


  @ApiProperty({ example: "*******" })
  @IsNotEmpty()
  password: string;
}
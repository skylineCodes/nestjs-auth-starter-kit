import { Resend } from 'resend';
import { Injectable, Logger } from '@nestjs/common';
import { NotifyEmailDTO } from './dto/notify-email.dto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class NotificationServiceService {
  private readonly resend: Resend;
  private readonly logger = new Logger(NotificationServiceService.name);

  constructor(private readonly configService: ConfigService) {
    this.resend = new Resend(this.configService.get('RESEND_API_KEY'));
  }

  async notifyEmail({ email, subject, text, html, attachments }: NotifyEmailDTO) {
    try {
      const response: any = await this.resend.emails.send({
        from: this.configService.getOrThrow('RESEND_FROM_EMAIL'),
        to: [email],
        subject,
        text,
        html,
        attachments,
      });

      console.log(this.configService.get('RESEND_API_KEY'))
      console.log(this.configService.get('RESEND_FROM_EMAIL'))
      console.log(`Email sent to ${email}: ${response?.id || 'No ID returned'}`);
      this.logger.log(`Email sent to ${email}: ${response?.id || 'No ID returned'}`);
    } catch (error) {
      this.logger.error(`Failed to send email to ${email}`, error);
      throw error;
    }
  }
}

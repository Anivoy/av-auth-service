import axios from "axios";
import { emailSendingConfig } from "../config/env.js";

export async function sendResetPassword({ name, recepient, token, resetUrlBase }) {
  try {
    const { EMAIL_API_URL, EMAIL_SENDING_KEY, EMAIL_USERNAME, EMAIL_DOMAIN, EMAIL_RESET_PASSWORD_TEMPLATE } = emailSendingConfig;

    if (!EMAIL_API_URL || !EMAIL_SENDING_KEY || !EMAIL_USERNAME || !EMAIL_DOMAIN || !EMAIL_RESET_PASSWORD_TEMPLATE) {
      throw new Error("Email sending config is incomplete");
    }

    const fullResetUrl = `${resetUrlBase}?token=${encodeURIComponent(token)}`;

    const body = {
      from: {
        address: `${EMAIL_USERNAME}@${EMAIL_DOMAIN}`,
        display_name: "Anivoy Team"
      },
      to: {
        address: recepient,
      },
      subject: "Reset your Anivoy password",
      template_id: EMAIL_RESET_PASSWORD_TEMPLATE,
      template_data: {
        name,
        reset_password_url: fullResetUrl
      }
    }

    await axios.post(EMAIL_API_URL, body, {
      headers: {
        Authorization: `Bearer ${EMAIL_SENDING_KEY}`,
        "Content-Type": "application/json",
      },
    });
  } catch (err) {
    console.error("Failed to send reset email:", err.message);
    throw err;
  }
}

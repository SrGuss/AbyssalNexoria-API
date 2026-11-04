export function accessCodeEmail({ code, purpose }) {
  const action = purpose === 'email_link'
    ? 'confirmar este e-mail'
    : purpose === 'admin_login' ? 'acessar o painel administrativo' : 'entrar na sua conta';
  const subject = purpose === 'admin_login'
    ? 'Seu código administrativo | Abyssal Nexoria'
    : 'Seu código de acesso | Abyssal Nexoria';
  const text = `Use o código ${code} para ${action}. Ele expira em 5 minutos. Se você não solicitou este código, ignore esta mensagem.`;
  const html = `<!doctype html>
<html lang="pt-BR">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${subject}</title></head>
<body style="margin:0;padding:24px;background:#090812;color:#f4f0ff;font-family:Arial,sans-serif">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;margin:0 auto;border:1px solid #34284d;border-radius:12px;background:#100e1d">
    <tr><td style="padding:32px 28px;text-align:center">
      <p style="margin:0 0 8px;color:#b9a0ff;font-size:12px;letter-spacing:2px">ABYSSAL NEXORIA</p>
      <h1 style="margin:0 0 18px;font-size:24px;color:#f4f0ff">Seu código de acesso</h1>
      <p style="margin:0 0 22px;color:#c1b8d2;font-size:14px;line-height:1.6">Use este código para ${action}:</p>
      <div style="display:inline-block;padding:16px 24px;border:1px solid #7254a8;border-radius:8px;background:#171226;color:#d9c8ff;font-size:32px;font-weight:bold;letter-spacing:8px">${code}</div>
      <p style="margin:22px 0 0;color:#a89db9;font-size:13px">Este código expira em <strong style="color:#cdbbff">5 minutos</strong> e só pode ser usado uma vez.</p>
      <p style="margin:18px 0 0;color:#847a94;font-size:12px;line-height:1.6">Se você não solicitou este código, ignore esta mensagem. Nunca compartilhe seu código.</p>
    </td></tr>
  </table>
</body>
</html>`;
  return { subject, html, text };
}

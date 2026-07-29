// Emergency Kit: the downloadable record of the two things Vault3 can never
// recover for the user. Generated entirely client-side (Blob + anchor) — the
// phrase never travels.

function download(filename: string, mime: string, content: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function downloadKitText(email: string, phrase: string): void {
  const created = new Date().toISOString().slice(0, 10);
  download(
    "vault3-emergency-kit.txt",
    "text/plain",
    [
      "VAULT3 EMERGENCY KIT",
      "====================",
      "",
      `Created:        ${created}`,
      `Account email:  ${email}`,
      "",
      "Secret Phrase (9 words, in order):",
      "",
      `    ${phrase}`,
      "",
      "Your Master Password is NOT in this kit — it lives in your head.",
      "",
      "Vault3 is zero-knowledge: without your Master Password AND this",
      "Secret Phrase, your vault cannot be opened by anyone, including",
      "Vault3. Keep this kit somewhere safe and offline (printed, in a",
      "drawer, in a safe). Do not store it next to your Master Password.",
      "",
      "Sign in at: https://vault3.com/login",
      "",
    ].join("\n"),
  );
}

export function downloadKitHTML(email: string, phrase: string): void {
  const created = new Date().toISOString().slice(0, 10);
  const words = phrase.split(" ");
  const cells = words
    .map(
      (word, i) =>
        `<td style="border:1px solid #ccc;border-radius:6px;padding:10px 14px;font-family:ui-monospace,Menlo,monospace;font-size:15px;"><span style="color:#888;font-size:11px;">${i + 1}.</span> ${word}</td>`,
    )
    .reduce<string[]>((rows, cell, i) => {
      if (i % 3 === 0) rows.push("");
      rows[rows.length - 1] += cell;
      return rows;
    }, [])
    .map((row) => `<tr>${row}</tr>`)
    .join("");

  download(
    "vault3-emergency-kit.html",
    "text/html",
    `<!doctype html>
<html><head><meta charset="utf-8"><title>Vault3 Emergency Kit</title></head>
<body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:640px;margin:40px auto;color:#14131c;">
<h1 style="letter-spacing:-1px;">vault<span style="color:#6d5ce6;">3</span> — Emergency Kit</h1>
<p style="color:#555;">Created ${created} · Print this page and keep it offline.</p>
<table style="border-collapse:separate;border-spacing:0 12px;width:100%;margin:24px 0;">
<tr><td style="color:#888;width:160px;padding:6px 0;">Account email</td><td style="font-weight:600;">${email}</td></tr>
<tr><td style="color:#888;padding:6px 0;">Master Password</td><td style="font-style:italic;color:#888;">write it here by hand: ______________________</td></tr>
</table>
<h2 style="font-size:17px;">Secret Phrase — 9 words, in order</h2>
<table style="border-collapse:separate;border-spacing:8px;">${cells}</table>
<p style="color:#555;font-size:14px;line-height:1.6;margin-top:24px;">
Vault3 is zero-knowledge: without your Master Password <strong>and</strong> this Secret Phrase,
your vault cannot be opened by anyone — including Vault3. Keep this kit somewhere safe
and offline. Never store it beside your Master Password.</p>
<p style="color:#888;font-size:13px;">Sign in at https://vault3.com/login</p>
</body></html>`,
  );
}

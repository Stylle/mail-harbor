# Zoom, settings scrolling and webhook formatting

Local maintenance, not yet published.

Responsive layout flags derive from the actual outer browser-window width. Page zoom changes the CSS viewport without changing those flags; real window resizes still select desktop/tablet/phone modes. Desktop/tablet keep minimum readable column widths and allow horizontal navigation when zoomed. No browser zoom shortcut or wheel event is canceled. Bounded app/main containers give settings their own vertical scroll area, including the wide-screen frame; navigation resets settings scroll to the top.

Blank Webhook templates emit only title/content. Content has allowed sender address, receiving account display name, an explicit time offset and original body with line breaks. Existing custom templates and raw-text variables are preserved; content is available as a new variable. Rule content modes remain the privacy boundary. The former additional12000-character cut is removed for full-body webhooks; adapter1MiB limits and attachment boundaries remain.

Validated with synthetic mail only: full existing browser regression, scroll/bottom-action access at375/834/1487/2560/3840, and125–250% CSS viewport zoom emulation with stable outer-window width. Backend tests cover JSON escaping, complete long body, default shape, notice privacy and custom-template compatibility. No real email, inbox or notification endpoint was used for validation. Physical browser/OS zoom gestures and Safari/iOS hardware are not claimed as tested.

# PQ Mail Privacy Policy

Effective date: November 17, 2026

PQ Mail is an experimental email application maintained by John Bradley. This policy describes the official PQ Mail desktop application, its optional Google integration, and the project website. Project: https://github.com/ve7jtb/pq-mail. Privacy contact: ve7jtb@gmail.com.

## What the application does

PQ Mail creates, signs, encrypts, reads, and verifies email on your device. It supports software private keys in password-protected PKCS#12 files and supported YubiKeys. Google sign-in is optional. You can use local email files or connect to other email providers without authorizing Google access. The Android preview does not currently implement Google OAuth; its local cryptography and configured mail-server connections are separate from the desktop Google integration.

## Google data and permissions

When you connect Gmail, PQ Mail requests these permissions:

- `gmail.readonly`: read mailbox information, message headers, messages, and attachments so you can browse your inbox and open email. The app also checks the authorized mailbox address against the account you selected.
- `gmail.send`: send the messages you explicitly choose to send, including locally signed or encrypted S/MIME messages.

PQ Mail does not request permission to delete Gmail messages, modify labels or read/unread state, or manage drafts. The read-only permission technically permits access beyond the inbox, but the current inbox interface lists messages in INBOX. The S/MIME filter examines message MIME headers; filtering does not verify a signature or establish that a sender is trusted.

PQ Mail communicates directly with Google's authorization and Gmail API services. Google receives authorization requests and API requests, including the content you submit when sending. Google and your mail provider process email under their own policies. PQ Mail's maintainer does not operate a mailbox relay or receive your messages, attachments, passwords, or OAuth tokens through the app.

## Local processing and storage

Gmail inbox pages hold up to 50 messages' headers in memory. The app retrieves raw message content when you open a message. It does not maintain a disk cache of Gmail bodies or attachments. Opened messages and decrypted content may remain in application memory while you use the app.

The app saves account addresses, server settings, identity references, public certificates, recipient contacts, certificate-fingerprint trust decisions, and YubiKey serial numbers and slot mappings locally. Public certificates can include names and email addresses. You may explicitly save email files and export certificates or software identities. Exported files, operating-system backups, and files you share remain under your control; they are not erased by signing out.

Google refresh tokens and custom OAuth client configuration are stored in macOS Keychain or Windows Credential Manager. Access tokens are held in memory. The shared desktop client configuration identifies the application; it is not your personal account token. Gmail password entry is handled by Google in your browser, not by PQ Mail. Credentials for other mail servers are used for the connection and are not saved by the app.

Software private keys remain in the encrypted identity files you create or import. Keys generated on a supported YubiKey remain on that device. PINs are used for the requested operation, may be reused in memory for that operation's composite components, and are cleared afterward. Device security, operating-system memory handling, backups, and third-party software also affect protection of local data.

## Use, sharing, and human access

Google user data is used only to provide the email features you request. PQ Mail does not sell it, use it for advertising, provide it to data brokers, or use it to train AI models. We follow the Google API Services User Data Policy, including its Limited Use requirements, for Google user data and data derived from it.

Sending email shares it with Google or your chosen mail server and the intended recipients. Email headers may remain visible even when the S/MIME body is encrypted. The app does not automatically upload your certificates, keys, messages, or diagnostic logs to GitHub or to the maintainer. It does not include advertising or analytics tracking.

If you voluntarily send information to the maintainer for support, only the information you provide is received. Please do not send PINs, passwords, tokens, or private keys, and redact unrelated message content. Support information is used to address your request and protect the project. It may be disclosed when legally required. We retain private support correspondence only as long as reasonably necessary for support, security, or legal obligations. Public GitHub issues and attachments are publicly visible and subject to GitHub's retention and removal controls.

## Your choices and deletion

- **Disconnect** closes the inbox connection; it does not revoke Google authorization.
- **Sign out of Google** clears the current token and requests removal of the saved refresh token from the operating-system credential store. If removal fails, the app reports the error; retry after unlocking the store. Client configuration remains.
- To revoke Google's authorization, remove PQ Mail from your Google Account's third-party connections at https://myaccount.google.com/connections. An older grant to a previous demo client must be removed separately.
- To remove local app settings and saved public identity/contact information, quit the app and remove its data directory: `~/Library/Application Support/Hybrid Mail` on macOS or `%LOCALAPPDATA%\Hybrid Mail` on Windows. The legacy directory name is retained for compatibility. Also remove any exported or imported files you no longer need and any associated backups. Uninstalling alone may leave those files and credential-store entries behind.
- Removing local certificates does not erase a YubiKey private key. Manage hardware keys separately; deleting them can permanently prevent decryption of older messages.

PQ Mail cannot erase messages retained by Google, another mail provider, or recipients. Use their controls for those copies. Contact ve7jtb@gmail.com about personal information you submitted directly to the maintainer.

## Website and third parties

The project website and source repository are hosted by GitHub. Visiting them may disclose technical request information, such as an IP address, to GitHub under its privacy policy. The project pages do not intentionally add analytics or advertising cookies. Google, GitHub, operating systems, certificate issuers, and other mail providers have their own policies and services; this policy does not replace them.

## Updates and contact

We will update this policy when relevant practices change and show the new effective date. Material changes to Google data access or use will be disclosed before that new use, with additional consent where required. This project is not directed to children. Contact John Bradley at ve7jtb@gmail.com with privacy questions.

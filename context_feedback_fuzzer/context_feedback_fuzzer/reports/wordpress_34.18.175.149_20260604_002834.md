# Context Feedback Fuzzer Report

- Target: `https://34.18.175.149/`
- Detected CMS: **wordpress**
- Requests sent: `337`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `unknown` / `unknown`

## Wordlist generation mechanism

Tool tạo wordlist theo 3 lớp: CMS paths từ profile/wordlist, extension paths theo server technology, và payload values theo loại parameter.

- Path wordlist sources: `wordpress.fuzz.txt, wp-plugins.fuzz.txt, wp-themes.fuzz.txt, urls-wordpress-3.3.1.txt`
- Server extension priority: `none`
- Parameter strategy examples:
  - `p` => `numeric`
  - `page_id` => `numeric`
  - `cat` => `numeric`
  - `search` => `text`
  - `s` => `text`
  - `author` => `numeric`
  - `action` => `action`
  - `nonce` => `generic`
  - `redirect_to` => `redirect`
  - `log` => `text`
  - `pwd` => `generic`

## Fingerprint scores

- wordpress: 0
- joomla: 0
- drupal: 0
- liferay: 0
- sharepoint: 0

## Findings

Các finding dưới đây là giả thuyết nguy cơ bug dựa trên phản hồi server, không phải xác nhận khai thác thành công hay chấm severity.

Không phát hiện dấu hiệu bất thường đáng kể.

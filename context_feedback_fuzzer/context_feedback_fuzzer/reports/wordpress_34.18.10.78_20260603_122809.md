# Context Feedback Fuzzer Report

- Target: `http://34.18.10.78/`
- Detected CMS: **wordpress**
- Requests sent: `400`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `php` / `apache`

## Wordlist generation mechanism

Tool tạo wordlist theo 3 lớp: CMS paths từ profile/wordlist, extension paths theo server technology, và payload values theo loại parameter.

- Path wordlist sources: `wordpress.fuzz.txt, wp-plugins.fuzz.txt, wp-themes.fuzz.txt, urls-wordpress-3.3.1.txt`
- Server extension priority: `.php, .php.bak, .php.old`
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

- wordpress: 17
- joomla: 0
- drupal: 0
- liferay: 0
- sharepoint: 0

## Findings

### 1. Possible SQL Injection - score 48
- Kind: `parameter` | Confidence: `High`
- URL: `http://34.18.10.78/readme.html?p=1%22`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword in response
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword in response

### 2. Possible SQL Injection - score 48
- Kind: `parameter` | Confidence: `High`
- URL: `http://34.18.10.78/readme.html?p=1%27`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword in response
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword in response

### 3. Input Reflection - score 30
- Kind: `parameter` | Confidence: `Medium`
- URL: `http://34.18.10.78/?log=%22cff_canary_9x7`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_canary_9x7`
- Status/Length/Type: `200` / `97562` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value reflected, but appears transformed/encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value reflected, but appears transformed/encoded

### 4. Input Reflection - score 30
- Kind: `parameter` | Confidence: `Medium`
- URL: `http://34.18.10.78/?log=%27cff_canary_9x7`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_canary_9x7`
- Status/Length/Type: `200` / `97562` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value reflected, but appears transformed/encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value reflected, but appears transformed/encoded

### 5. Input Reflection - score 30
- Kind: `parameter` | Confidence: `Medium`
- URL: `http://34.18.10.78/?log=%3Ccff_canary_9x7%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_canary_9x7&gt;`
- Status/Length/Type: `200` / `97590` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value reflected, but appears transformed/encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value reflected, but appears transformed/encoded

### 6. Input Reflection - score 30
- Kind: `parameter` | Confidence: `Medium`
- URL: `http://34.18.10.78/?s=%22cff_canary_9x7`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_canary_9x7`
- Status/Length/Type: `200` / `61935` / `text/html; charset=UTF-8`
- Title: Search Results for “&quot;cff_canary_9x7” – WordPress on Google Compute Engine
- Evidence: canary value reflected, but appears transformed/encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value reflected, but appears transformed/encoded

### 7. Input Reflection - score 30
- Kind: `parameter` | Confidence: `Medium`
- URL: `http://34.18.10.78/?s=%27cff_canary_9x7`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_canary_9x7`
- Status/Length/Type: `200` / `61935` / `text/html; charset=UTF-8`
- Title: Search Results for “&#x27;cff_canary_9x7” – WordPress on Google Compute Engine
- Evidence: canary value reflected, but appears transformed/encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value reflected, but appears transformed/encoded

### 8. Input Reflection - score 30
- Kind: `parameter` | Confidence: `Medium`
- URL: `http://34.18.10.78/?s=%3Ccff_canary_9x7%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_canary_9x7&gt;`
- Status/Length/Type: `200` / `61965` / `text/html; charset=UTF-8`
- Title: Search Results for “&lt;cff_canary_9x7&gt;” – WordPress on Google Compute Engine
- Evidence: canary value reflected, but appears transformed/encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value reflected, but appears transformed/encoded

### 9. Input Reflection - score 30
- Kind: `parameter` | Confidence: `Medium`
- URL: `http://34.18.10.78/?search=%22cff_canary_9x7`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_canary_9x7`
- Status/Length/Type: `200` / `99313` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value reflected, but appears transformed/encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value reflected, but appears transformed/encoded

### 10. Input Reflection - score 30
- Kind: `parameter` | Confidence: `Medium`
- URL: `http://34.18.10.78/?search=%27cff_canary_9x7`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_canary_9x7`
- Status/Length/Type: `200` / `99313` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value reflected, but appears transformed/encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value reflected, but appears transformed/encoded

### 11. Input Reflection - score 30
- Kind: `parameter` | Confidence: `Medium`
- URL: `http://34.18.10.78/?search=%3Ccff_canary_9x7%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_canary_9x7&gt;`
- Status/Length/Type: `200` / `99331` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value reflected, but appears transformed/encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value reflected, but appears transformed/encoded

### 12. Parameter behavior anomaly - score 26
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/readme.html?p=-1`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 13. Parameter behavior anomaly - score 26
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/readme.html?p=0`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 14. Parameter behavior anomaly - score 26
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/readme.html?p=1`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 15. Parameter behavior anomaly - score 26
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/readme.html?p=999999`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 16. Parameter behavior anomaly - score 26
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/readme.html?page_id=-1`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 17. Parameter behavior anomaly - score 26
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/readme.html?page_id=0`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 18. Parameter behavior anomaly - score 26
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/readme.html?page_id=1`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 19. Parameter behavior anomaly - score 26
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/readme.html?page_id=999999`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 20. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?action=%27`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Status/Length/Type: `200` / `97452` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 21. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?action=cff_canary_9x7`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_canary_9x7`
- Status/Length/Type: `200` / `97556` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 22. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?action=invalid_action`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action`
- Status/Length/Type: `200` / `97556` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 23. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?author=0`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Status/Length/Type: `200` / `99217` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 24. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?author=1`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Status/Length/Type: `200` / `99768` / `text/html; charset=UTF-8`
- Title: admin – WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 25. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?author=1%22`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Status/Length/Type: `200` / `99786` / `text/html; charset=UTF-8`
- Title: admin – WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 26. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?author=1%27`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Status/Length/Type: `200` / `99786` / `text/html; charset=UTF-8`
- Title: admin – WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 27. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?cat=-1`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Status/Length/Type: `200` / `100577` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 28. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?cat=0`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Status/Length/Type: `200` / `99199` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 29. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?cat=1`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Status/Length/Type: `200` / `78025` / `text/html; charset=UTF-8`
- Title: Uncategorized – WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 30. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?log=%27`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Status/Length/Type: `200` / `97422` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 31. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?log=cff_canary_9x7`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_canary_9x7`
- Status/Length/Type: `200` / `97526` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 32. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?nonce=%27`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Status/Length/Type: `200` / `97442` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 33. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?nonce=12345`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345`
- Status/Length/Type: `200` / `97456` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 34. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?nonce=cff_canary_9x7`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_canary_9x7`
- Status/Length/Type: `200` / `97546` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 35. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?nonce=true`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true`
- Status/Length/Type: `200` / `97446` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 36. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?p=-1`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Status/Length/Type: `200` / `65144` / `text/html; charset=UTF-8`
- Title: Page not found – WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 37. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?p=0`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Status/Length/Type: `200` / `99187` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 38. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?p=1`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Status/Length/Type: `200` / `68180` / `text/html; charset=UTF-8`
- Title: Hello world! – WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 39. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?page_id=0`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Status/Length/Type: `200` / `99223` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 40. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?pwd=%27`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Status/Length/Type: `200` / `97422` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 41. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?pwd=12345`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345`
- Status/Length/Type: `200` / `97436` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 42. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?pwd=cff_canary_9x7`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_canary_9x7`
- Status/Length/Type: `200` / `97526` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 43. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?pwd=true`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true`
- Status/Length/Type: `200` / `97426` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 44. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?redirect_to=%2F%2Fexample.com%2Fcff_canary_9x7`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_canary_9x7`
- Status/Length/Type: `200` / `97794` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 45. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?redirect_to=https%3A%2F%2Fexample.com%2Fcff_canary_9x7`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_canary_9x7`
- Status/Length/Type: `200` / `97870` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 46. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?s=%27`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Status/Length/Type: `200` / `75033` / `text/html; charset=UTF-8`
- Title: Search Results for “&#x27;” – WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 47. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?s=cff_canary_9x7`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_canary_9x7`
- Status/Length/Type: `200` / `61873` / `text/html; charset=UTF-8`
- Title: Search Results for “cff_canary_9x7” – WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 48. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?search=%27`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Status/Length/Type: `200` / `99229` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 49. Parameter behavior anomaly - score 22
- Kind: `parameter` | Confidence: `Low`
- URL: `http://34.18.10.78/?search=cff_canary_9x7`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_canary_9x7`
- Status/Length/Type: `200` / `99295` / `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 50. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/license.txt`
- Status/Length/Type: `200` / `19903` / `text/plain`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 51. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/readme.html`
- Status/Length/Type: `200` / `7406` / `text/html`
- Title: WordPress › ReadMe
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 52. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/`
- Status/Length/Type: `200` / `22626` / `text/html;charset=UTF-8`
- Title: Index of /wp-admin/css
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 53. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/color-picker-rtl.css`
- Status/Length/Type: `200` / `3957` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 54. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/color-picker-rtl.min.css`
- Status/Length/Type: `200` / `3201` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 55. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/color-picker.css`
- Status/Length/Type: `200` / `3919` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 56. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/color-picker.min.css`
- Status/Length/Type: `200` / `3198` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 57. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/customize-controls-rtl.css`
- Status/Length/Type: `200` / `72569` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 58. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/customize-controls-rtl.min.css`
- Status/Length/Type: `200` / `60473` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 59. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/customize-controls.css`
- Status/Length/Type: `200` / `72491` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 60. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/customize-controls.min.css`
- Status/Length/Type: `200` / `60430` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 61. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/dashboard-rtl.css`
- Status/Length/Type: `200` / `30439` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 62. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/dashboard.css`
- Status/Length/Type: `200` / `30409` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 63. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/install-rtl.css`
- Status/Length/Type: `200` / `6497` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 64. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/install.css`
- Status/Length/Type: `200` / `6464` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 65. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/install.min.css`
- Status/Length/Type: `200` / `5266` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 66. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/login-rtl.css`
- Status/Length/Type: `200` / `8291` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 67. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/login.css`
- Status/Length/Type: `200` / `8253` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 68. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/media-rtl.css`
- Status/Length/Type: `200` / `28190` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 69. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/media-rtl.min.css`
- Status/Length/Type: `200` / `22694` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 70. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/media.css`
- Status/Length/Type: `200` / `28139` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 71. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/media.min.css`
- Status/Length/Type: `200` / `22678` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 72. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/widgets-rtl.css`
- Status/Length/Type: `200` / `17887` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 73. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/widgets.css`
- Status/Length/Type: `200` / `17850` / `text/css`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 74. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/`
- Status/Length/Type: `200` / `20124` / `text/html;charset=UTF-8`
- Title: Index of /wp-admin/images
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 75. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/arrows-2x.png`
- Status/Length/Type: `200` / `863` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 76. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/date-button-2x.gif`
- Status/Length/Type: `200` / `996` / `image/gif`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 77. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/icons32-2x.png`
- Status/Length/Type: `200` / `21770` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 78. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/icons32-vs-2x.png`
- Status/Length/Type: `200` / `21396` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 79. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/icons32-vs.png`
- Status/Length/Type: `200` / `8007` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 80. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/icons32.png`
- Status/Length/Type: `200` / `8023` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 81. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/imgedit-icons-2x.png`
- Status/Length/Type: `200` / `7664` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 82. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/imgedit-icons.png`
- Status/Length/Type: `200` / `4055` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 83. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/list-2x.png`
- Status/Length/Type: `200` / `1523` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 84. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/list.png`
- Status/Length/Type: `200` / `1003` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 85. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/loading.gif`
- Status/Length/Type: `200` / `1368` / `image/gif`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 86. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/mask.png`
- Status/Length/Type: `200` / `2001` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 87. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/media-button-2x.png`
- Status/Length/Type: `200` / `850` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 88. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/menu-2x.png`
- Status/Length/Type: `200` / `12672` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 89. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/menu-vs-2x.png`
- Status/Length/Type: `200` / `12453` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 90. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/menu-vs.png`
- Status/Length/Type: `200` / `5086` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 91. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/menu.png`
- Status/Length/Type: `200` / `5039` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 92. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/post-formats-vs.png`
- Status/Length/Type: `200` / `2450` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 93. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/post-formats.png`
- Status/Length/Type: `200` / `2157` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 94. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/post-formats32-vs.png`
- Status/Length/Type: `200` / `5111` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 95. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/post-formats32.png`
- Status/Length/Type: `200` / `5142` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 96. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/stars-2x.png`
- Status/Length/Type: `200` / `1257` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 97. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/stars.png`
- Status/Length/Type: `200` / `924` / `image/png`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 98. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/plugins/akismet/readme.txt`
- Status/Length/Type: `200` / `6329` / `text/plain`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 99. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/plugins/contact-form-7/readme.txt`
- Status/Length/Type: `200` / `4825` / `text/plain`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 100. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/plugins/woocommerce/readme.txt`
- Status/Length/Type: `200` / `22170` / `text/plain`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 101. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/themes/twentytwentythree/readme.txt`
- Status/Length/Type: `200` / `3075` / `text/plain`
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 102. Informational - score 22
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-login.php`
- Status/Length/Type: `200` / `5565` / `text/html; charset=UTF-8`
- Title: Log In ‹ WordPress on Google Compute Engine — WordPress
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 103. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/admin-footer.php`
- Status/Length/Type: `200` / `2` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 104. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/admin-functions.php`
- Status/Length/Type: `200` / `2` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 105. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/admin-header.php`
- Status/Length/Type: `200` / `2` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 106. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/admin-post.php`
- Status/Length/Type: `200` / `0` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 107. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/farbtastic-rtl.css`
- Status/Length/Type: `200` / `647` / `text/css`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 108. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/farbtastic.css`
- Status/Length/Type: `200` / `611` / `text/css`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 109. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/wp-admin-rtl.css`
- Status/Length/Type: `200` / `490` / `text/css`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 110. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/wp-admin-rtl.min.css`
- Status/Length/Type: `200` / `550` / `text/css`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 111. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/wp-admin.css`
- Status/Length/Type: `200` / `395` / `text/css`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 112. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/css/wp-admin.min.css`
- Status/Length/Type: `200` / `490` / `text/css`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 113. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/custom-background.php`
- Status/Length/Type: `200` / `2` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 114. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/custom-header.php`
- Status/Length/Type: `200` / `2` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 115. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/edit-form-advanced.php`
- Status/Length/Type: `200` / `2` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 116. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/edit-form-comment.php`
- Status/Length/Type: `200` / `2` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 117. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/edit-link-form.php`
- Status/Length/Type: `200` / `2` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 118. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/edit-tag-form.php`
- Status/Length/Type: `200` / `2` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 119. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/align-center-2x.png`
- Status/Length/Type: `200` / `147` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 120. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/align-center.png`
- Status/Length/Type: `200` / `546` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 121. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/align-left-2x.png`
- Status/Length/Type: `200` / `143` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 122. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/align-left.png`
- Status/Length/Type: `200` / `554` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 123. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/align-none-2x.png`
- Status/Length/Type: `200` / `121` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 124. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/align-none.png`
- Status/Length/Type: `200` / `417` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 125. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/align-right-2x.png`
- Status/Length/Type: `200` / `142` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 126. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/align-right.png`
- Status/Length/Type: `200` / `509` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 127. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/arrows.png`
- Status/Length/Type: `200` / `243` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 128. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/bubble_bg-2x.gif`
- Status/Length/Type: `200` / `424` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 129. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/bubble_bg.gif`
- Status/Length/Type: `200` / `398` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 130. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/comment-grey-bubble-2x.png`
- Status/Length/Type: `200` / `258` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 131. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/comment-grey-bubble.png`
- Status/Length/Type: `200` / `114` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 132. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/date-button.gif`
- Status/Length/Type: `200` / `400` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 133. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/generic.png`
- Status/Length/Type: `200` / `719` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 134. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/marker.png`
- Status/Length/Type: `200` / `360` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 135. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/media-button-image.gif`
- Status/Length/Type: `200` / `200` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 136. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/media-button-music.gif`
- Status/Length/Type: `200` / `206` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 137. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/media-button-other.gif`
- Status/Length/Type: `200` / `248` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 138. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/media-button-video.gif`
- Status/Length/Type: `200` / `133` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 139. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/media-button.png`
- Status/Length/Type: `200` / `323` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 140. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/no.png`
- Status/Length/Type: `200` / `755` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 141. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/resize-2x.gif`
- Status/Length/Type: `200` / `151` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 142. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/resize-rtl-2x.gif`
- Status/Length/Type: `200` / `150` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 143. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/resize-rtl.gif`
- Status/Length/Type: `200` / `70` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 144. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/resize.gif`
- Status/Length/Type: `200` / `64` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 145. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/se.png`
- Status/Length/Type: `200` / `120` / `image/png`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 146. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/sort-2x.gif`
- Status/Length/Type: `200` / `97` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 147. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/images/sort.gif`
- Status/Length/Type: `200` / `55` / `image/gif`
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 148. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 149. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/about.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 150. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/admin.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 151. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/async-upload.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 152. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/comment.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 153. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/credits.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 154. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/customize.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 155. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/edit-comments.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 156. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/edit-tags.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 157. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/edit.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 158. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/export.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 159. Informational - score 19
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-admin/freedoms.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 160. Informational - score 18
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/plugins/contact-form-7/`
- Status/Length/Type: `200` / `2781` / `text/html;charset=UTF-8`
- Title: Index of /wp-content/plugins/contact-form-7
- Reason: status=200; different from 404 baseline; length delta

### 161. Informational - score 18
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/plugins/woocommerce/`
- Status/Length/Type: `200` / `3538` / `text/html;charset=UTF-8`
- Title: Index of /wp-content/plugins/woocommerce
- Reason: status=200; different from 404 baseline; length delta

### 162. Informational - score 18
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/themes/twentytwentythree/`
- Status/Length/Type: `200` / `2560` / `text/html;charset=UTF-8`
- Title: Index of /wp-content/themes/twentytwentythree
- Reason: status=200; different from 404 baseline; length delta

### 163. Informational - score 18
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/uploads/`
- Status/Length/Type: `200` / `3922` / `text/html;charset=UTF-8`
- Title: Index of /wp-content/uploads
- Reason: status=200; different from 404 baseline; length delta

### 164. Informational - score 18
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-includes/`
- Status/Length/Type: `200` / `63990` / `text/html;charset=UTF-8`
- Title: Index of /wp-includes
- Reason: status=200; different from 404 baseline; length delta

### 165. Informational - score 15
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/`
- Status/Length/Type: `200` / `0` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline

### 166. Informational - score 15
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/index.php`
- Status/Length/Type: `200` / `0` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline

### 167. Informational - score 15
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/plugins/akismet/`
- Status/Length/Type: `200` / `0` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline

### 168. Informational - score 15
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-content/plugins/akismet/index.php`
- Status/Length/Type: `200` / `0` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline

### 169. Informational - score 15
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-cron.php`
- Status/Length/Type: `200` / `0` / `text/html; charset=UTF-8`
- Reason: status=200; different from 404 baseline

### 170. Informational - score 15
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/index.php`
- Status/Length/Type: `301` / `0` / `text/html; charset=UTF-8`
- Reason: status=301; different from 404 baseline

### 171. Informational - score 15
- Kind: `path` | Confidence: `Low`
- URL: `http://34.18.10.78/wp-activate.php`
- Status/Length/Type: `302` / `0` / `text/html; charset=UTF-8`
- Reason: status=302; different from 404 baseline


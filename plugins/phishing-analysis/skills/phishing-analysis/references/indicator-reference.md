# Phishing Indicator Reference

## Suspicious TLDs

TLDs frequently used in phishing campaigns:

`.xyz` `.top` `.click` `.link` `.work` `.date` `.download` `.win` `.bid` `.stream` `.racing` `.review` `.cricket` `.science` `.party` `.gq` `.cf` `.ga` `.ml` `.tk` `.vip` `.icu` `.buzz` `.monster` `.loan` `.online` `.site` `.club` `.wang` `.men` `.cam` `.rest` `.life` `.live` `.space` `.tech` `.store` `.fun` `.zone` `.pro` `.pw` `.cc` `.su` `.cn` `.ru` `.ua`

## Commonly Spoofed Brands

`paypal` `amazon` `apple` `microsoft` `google` `facebook` `netflix` `bank` `chase` `wellsfargo` `citibank` `usps` `fedex` `dhl` `ups` `irs` `dropbox` `linkedin` `coinbase`

## Dangerous File Extensions

### Critical Risk
`.exe` `.scr` `.bat` `.cmd` `.com` `.pif` `.vbs` `.vbe` `.js` `.jse` `.ws` `.wsf` `.msc` `.msi` `.hta`

### High Risk (Archives)
`.zip` `.rar` `.7z` `.tar` `.gz` `.iso` `.img`

### Medium Risk (Macro-enabled)
`.doc` `.docm` `.xls` `.xlsm` `.ppt` `.pptm` `.pdf`

### Low Risk
`.docx` `.xlsx` `.pptx` `.txt` `.csv`

## URL Shorteners

`bit.ly` `tinyurl.com` `t.co` `goo.gl` `ow.ly` `is.gd` `buff.ly` `rebrand.ly` `cutt.ly` `short.io`

## ISP Email Domains

Consumer ISP domains that should not send transactional/business emails:

`windstream.net` `comcast.net` `verizon.net` `att.net` `cox.net` `charter.net` `spectrum.net` `frontier.com` `centurylink.net` `earthlink.net`

## Government/Postal Impersonation Keywords

| Keyword | Legitimate Domain |
|---------|------------------|
| usps | usps.com |
| royal mail | royalmail.com |
| canada post | canadapost.ca |
| irs | irs.gov |
| hmrc | gov.uk |

## Urgency Patterns

`act now` `immediately` `within 24 hours` `account will be closed` `last chance` `final warning` `expires today` `don't delay`

## Gibberish Domain Detection

Domains are flagged as potentially randomly generated when:
- Shannon entropy > 2.3 AND vowel ratio < 25%
- Shannon entropy > 3.8 (regardless of vowel ratio)
- Contains 4+ consecutive consonants
- No vowels in domain name (5+ characters)

Normal English words: entropy 2.5-3.5, vowel ratio ~40%

## References

- [CISA Phishing Guide](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing)
- [Google Email Headers](https://support.google.com/mail/answer/29436)
- [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search)
- [CISA Attachment Safety](https://www.cisa.gov/news-events/news/using-caution-email-attachments)
- [SPF/DKIM Guide](https://support.google.com/a/answer/33786)

# Defender's Window

How long defenders get between a vulnerability's public disclosure and its first reported exploitation in the wild: the median, by CVE publication year since 2021.

Live site: https://bertug.github.io/defenders-window/

- **Exploitation dates:** [VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV)](https://vulncheck.com/kev), Community edition. Public use requires attribution to VulnCheck KEV.
- **Publication dates:** [CVE.org](https://github.com/CVEProject/cvelistV5) `cveMetadata.datePublished`.

Recent years look faster than they are: older CVEs have had more time to collect late exploitation reports. The page states this caveat.

## How it updates

The site updates itself once a day. A scheduled GitHub Actions job pulls the latest VulnCheck KEV data, matches it with CVE.org publication dates, rebuilds the page and publishes it to GitHub Pages.

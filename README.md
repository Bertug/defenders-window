# Defender's Window

How long defenders get between a vulnerability's public disclosure and its first reported exploitation in the wild: the median, by CVE publication year since 2021.

Live site: https://bertug.github.io/defenders-window/

- **Exploitation dates:** [VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV)](https://vulncheck.com/kev), Community edition. Public use requires attribution to VulnCheck KEV.
- **Publication dates:** [CVE.org](https://github.com/CVEProject/cvelistV5) `cveMetadata.datePublished`.

Recent years look faster than they are: older CVEs have had more time to collect late exploitation reports. The page states this caveat.

## How it updates

A GitHub Actions workflow runs daily. It downloads VulnCheck KEV using the `VULNCHECK_API_TOKEN` repository secret, rebuilds `index.html`, commits the refreshed data and deploys to GitHub Pages. The website itself never contains or needs the token.

## Local use

```
npm run set-token   # stores the token encrypted for your Windows user (DPAPI)
npm run refresh     # downloads data using the stored token
npm run build       # writes index.html
npm test
npm start           # preview at http://127.0.0.1:8875
```

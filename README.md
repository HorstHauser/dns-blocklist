# DNS-Sperrliste für die FRITZ!Box

Täglich zusammengeführte Domainliste für den eingebauten DNS-Filter von
FRITZ!OS 8.5x (getestet gegen die Dokumentation der FRITZ!Box 6690 Cable).
Format: eine Domain pro Zeile (AVM-Bezeichnung: *wildcard domains*).

## In der FRITZ!Box eintragen

Unter *Heimnetz > Netzwerk > Netzwerkeinstellungen > Erweiterte
Netzwerkeinstellungen ändern > DNS-Filter* eine Filterliste hinzufügen.
Nach einem Push nach `main` lautet die Abrufadresse:

```
https://raw.githubusercontent.com/HorstHauser/dns-blocklist/main/blocklist.txt
```

GitHub-Raw-URLs sind HTTPS. AVM empfiehlt bei Zertifikatsproblemen
(historisch u. a. fehlendes Sectigo-Root in FRITZ!OS) genau solche
GitHub-Adressen als Alternative zu anderen Hostern.

## Quellen

| Quelle | URL | Lizenz |
| --- | --- | --- |
| [OISD Big](https://oisd.nl) | https://big.oisd.nl | [GPL-3.0](https://oisd.nl/faq) |
| [HaGeZi Pro](https://github.com/hagezi/dns-blocklists) | https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt | [GPL-3.0](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE) |
| [Steven Black Hosts](https://github.com/StevenBlack/hosts) | https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | [MIT](https://github.com/StevenBlack/hosts/blob/master/license.txt) |

Die zusammengeführte Liste steht wegen der GPL-Quellen unter GPL-3.0
(siehe `LICENSE`). Die MIT-Lizenz von Steven Black ist damit vereinbar;
der Copyright-Hinweis bleibt in diesem README erhalten.

AVM nennt dieselben drei Listen als Beispiele in der Wissensdatenbank
[#4463](https://uk.fritz.com/service/knowledge-base/dok/FRITZ-Box-7590/4463_Configuring-DNS-filters-in-the-FRITZ-Box/).
Hier werden sie normalisiert, dedupliziert und als eine Datei bereitgestellt,
damit die Box nicht drei überlappende Listen laden und speichern muss.

## Ausnahmen pflegen

Gewünschte Freigaben in `allowlist.txt` eintragen (eine Domain pro Zeile,
`#` beginnt einen Kommentar). Beim nächsten Lauf entfallen diese Domains
und ihre Subdomains in `blocklist.txt`.

Zusätzlich kann die Box eigene Domain-Ausnahmen verwalten; erlaubte
Einträge haben dort Vorrang vor Filterlisten (AVM #4463).

## Täglicher Lauf

GitHub Actions (`.github/workflows/build.yml`) baut die Liste täglich um
03:17 UTC und bei manuellem `workflow_dispatch`. `blocklist.txt` und
`stats.json` werden nur bei Änderungen nach `main` geschrieben. Schlägt
der Download oder die Plausibilitätsprüfung fehl (Quelle fehlt oder
weniger als 50 % der letzten Domainzahl), endet der Workflow mit Fehler
und überschreibt die bestehende Liste nicht.

Lokal:

```bash
python3 scripts/build.py
```

Optional, standardmäßig aus:

```bash
python3 scripts/build.py --collapse-subdomains
```

Das entfernt Subdomains, deren Elterndomain bereits gesperrt ist. HaGeZi
dokumentiert, dass die FRITZ!Box das *Wildcard-Domains*-Format so
interpretiert (eine Zeile `example.com` deckt auch Subdomains ab). AVM
nennt das Format „wildcard domains“, bestätigt das Mitsperren aber nicht
ausdrücklich in #4463. Deshalb bleibt die Option aus, bis das am Gerät
geprüft wurde.

## Hinweise

- Der Filter wirkt nur auf Geräte, die den DNS-Server der FRITZ!Box nutzen.
- Eine feste Eintragsobergrenze veröffentlicht AVM nicht; der begrenzende
  Faktor ist der interne Speicher („Zu wenig persistenter Speicher vorhanden“).
- Das 500-Einträge-Limit gilt nur für die älteren Listen der Kindersicherung,
  nicht für diesen DNS-Filter.
- Browser-Listen wie EasyList sind ungeeignet (Pfade, Kosmetikregeln).

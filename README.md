# checkURLwithVirusTotal

Ein einfaches Python-Skript zur automatisierten Überprüfung von URLs mithilfe der [VirusTotal API](https://developers.virustotal.com/reference).

## 🔍 Zweck

Das Skript wurde im Rahmen des [GoEuropean Projekts](https://www.goeuropean.org/) entwickelt, um externe Links automatisiert auf potenzielle Gefahren zu prüfen. Es verarbeitet eine CSV-Datei mit URLs, sendet sie an die VirusTotal API und speichert die Analyseergebnisse strukturiert in Ergebnisdateien.

## 🚀 Features

- Nutzung der öffentlichen VirusTotal v3 API
- Keine externen Libraries (nur `requests` und `csv`)
- Base64-Encoding der URLs (API-Anforderung)
- Retry-Logik bei verzögerten Analysen (404)
- Saubere Trennung zwischen erfolgreichen und fehlgeschlagenen Scans

## 📦 Installation

```bash
git clone https://github.com/ascdata/checkURLwithVirusTotal.git
cd checkURLwithVirusTotal
pip install -r requirements.txt
```

## 🛡️ API-Key einrichten

- Erstelle eine Datei `apikey.txt` im Projektverzeichnis.
- Füge deinen VirusTotal API-Key als einzige Zeile ein.
- Achte darauf, dass `apikey.txt` in `.gitignore` steht.

## 🧪 Verwendung

```bash
python3 check_urls.py
```

- **Eingabe:** CSV-Datei mit URLs (Pfad im Script definieren)
- **Ausgabe:**
    - `scan_results.csv`: Erfolgreiche Analysen
    - `failed_scans.csv`: Nicht analysierbare URLs (z. B. API-Limit oder noch keine Daten)

## 📊 Beispielausgabe

```csv
url,harmless,suspicious,malicious,undetected
https://example.com,68,0,1,3
```

## 📌 Hinweis

Das Tool pausiert automatisch zwischen API-Anfragen, um das öffentliche Anfrage-Limit der VirusTotal API einzuhalten (max. 4 pro Minute).

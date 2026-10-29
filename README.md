# Agentický systém pre predikciu útoku a reakciu v reálnom čase

**Tímový projekt 2026/2027**  
**Slovenská technická univerzita v Bratislave**  
Fakulta elektrotechniky a informatiky (FEI STU)  
*Partner / Zadávateľ:* Ing. Lukáš Šurab (v spolupráci s Alison Slovakia s.r.o.)

---

## 📌 Prehľad projektu

Tradičné SIEM/SOC systémy a reakcie na incidenty (Incident Response) väčšinou fungujú na základe statických pravidiel a reakcia prebieha až po kompromitácii aktív. Tento projekt sa zameriava na vývoj autonómneho agentického systému, ktorý v reálnom čase spracováva bezpečnostné logy, stavia dynamický kontext incidentu a predikuje ďalšie pravdepodobné kroky útočníka.

Namiesto pasívneho reportovania udalostí agent generuje hypotézy o prebiehajúcom útoku, mapuje ich na rámec **MITRE ATT&CK** a navrhuje defenzívne opatrenia s ohľadom na ich dopad na bežnú prevádzku.

---

## 🏗️ Architektúra a Tok dát

Systém je rozdelený na dátovú pipeline pre zber a spracovanie telemetry a agentickú vrstvu pre autonómnu analýzu.

```
[ Zdroje / Telemetria ]
        │
        ▼
    Filebeat          (Zber a odosielanie logov z koncových uzlov)
        │
        ▼
  Apache Kafka        (Message broker pre distribuovaný real-time stream)
        │
        ▼
     Logstash         (Parsing, normalizácia a enrichovanie dát)
        │
        ▼
  Elasticsearch       (Indexovanie a rýchle vyhľadávanie v telemetrii)
        │
        ▼
   [ Agentic Core ]   (LangGraph + Qwen / DeepSeek)
```

---

## 🛠️ Použité technológie

### Ingestion & Data Pipeline
* **Filebeat** – ľahký agent na zber a streamovanie logov z cieľových prostredí.
* **Apache Kafka** – správca správ (event-streaming platforma) pre bezpečné a škálovateľné spracovanie toku logov v reálnom čase.
* **Logstash** – spracovanie, filtrovanie a štruktúrovanie nespracovaných dát.
* **Elasticsearch** – centrálne úložisko pre spracované bezpečnostné udalosti a vy vyhľadávanie v telemetrii.

### Agentic Intelligence & Orchestration
* **LangGraph** – rámec na vybudovanie cyklického, stavového agentického grafu (rozhodovací proces, tvorba hypotéz, hodnotiaca slučka).
* **Qwen / DeepSeek** – lokálne/open-source LLM modely na analýzu logov, uvažovanie nad technikami útočníka a návrh reakcií.
* **MITRE ATT&CK** – znalostná báza na mapovanie a klasifikáciu taktických krokov útočníka.

### Infraštruktúra & Prostredie
* **Python 3.x** – primárny jazyk pre vývoj agenta a integráciu.
* **Podman / Podman Compose** – kontajnerizácia a izolácia testovacieho prostredia (Sandbox).

---

## 🎯 Hlavné ciele a vlastnosti

1. **Dynamický dátový model**: Priebežné mapovanie vzťahov medzi sieťovými aktívami a indikátormi kompromitácie (IoC).
2. **Real-time korelácia**: Aktualizácia kontextu incidentu bezprostredne po príchode nových udalostí do pipeline.
3. **Prediktívny agent**: Analyzovanie stavu útoku, odhadovanie ďalšej fázy (Kill Chain) a navrhovanie adekvátnych protiváhových zásahov.
4. **Hodnotiaci systém reakcií**: Simulácia a porovnanie navrhovaných defenzívnych zásahov (nating, izolácia, blokovanie IP) s cieľom minimalizovať dopad na produkčnú prevádzku.
5. **Validácia**: Testovanie na reálnych incidentných scenároch pre meranie efektivity a zníženia záťaže SOC analytikov.

---

## 👥 Spoznaj tím

* **Damián Danko** (`I-API-CYBERSEC`)
* **Marco Dzurilla** (`I-API-CYBERSEC`)
* **Adam Hoffmann** (`I-API-AI`)
* **Boris Pekarčík** (`I-API-CYBERSEC`)
* **Rudolf Tisoň** (`I-API-CYBERSEC`)

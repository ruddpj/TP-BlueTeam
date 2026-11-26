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

TBD

---

## 🛠️ Použité technológie

TBD

---

## 🎯 Hlavné ciele a vlastnosti

1. **Dynamický dátový model**: Priebežné mapovanie vzťahov medzi sieťovými aktívami a indikátormi kompromitácie (IoC).
2. **Real-time korelácia**: Aktualizácia kontextu incidentu bezprostredne po príchode nových udalostí do pipeline.
3. **Prediktívny agent**: Analyzovanie stavu útoku, odhadovanie ďalšej fázy (Kill Chain) a navrhovanie adekvátnych protiváhových zásahov.
4. **Hodnotiaci systém reakcií**: Simulácia a porovnanie navrhovaných defenzívnych zásahov (nating, izolácia, blokovanie IP) s cieľom minimalizovať dopad na produkčnú prevádzku.
5. **Validácia**: Testovanie na reálnych incidentných scenároch pre meranie efektivity a zníženia záťaže SOC analytikov.

---

## 📝 Zápisnice zo stretnutí

Zápisnice dokumentujú priebeh tímových stretnutí, prijaté
rozhodnutia, konzultácie s vedúcim projektu a úlohy členov tímu.

| Zápisnica | Dátum stretnutia | Hlavné zameranie stretnutia | Dokument |
| :--- | :---: | :--- | :---: |
| Zápisnica č. 1/2026 | 07.10.2026 | Úvodné stretnutie a organizácia projektu | [📄 PDF](docs/zapisnice/Zápisnica%20č.%201_2026.pdf) |
| Zápisnica č. 2/2026 | 15.10.2026 | Existujúce riešenia a serverová infraštruktúra | [📄 PDF](docs/zapisnice/Zápisnica%20č.%202_2026.pdf) |
| Zápisnica č. 3/2026 | 22.10.2026 | Stav infraštruktúry a koncept riešenia | [📄 PDF](docs/zapisnice/Zápisnica%20č.%203_2026.pdf) |
| Zápisnica č. 4/2026 | 27.10.2026 | Abstrakt zadania a rozdelenie úloh | [📄 PDF](docs/zapisnice/Zápisnica%20č.%204_2026.pdf) |
| Zápisnica č. 5/2026 | 29.10.2026 | Spracovanie logov a návrh agentického systému | [📄 PDF](docs/zapisnice/Zápisnica%20č.%205_2026.pdf) |
| Zápisnica č. 6/2026 | 05.11.2026 | Architektúra systému a integrácia technológií | [📄 PDF](docs/zapisnice/Zápisnica%20č.%206_2026.pdf) |
| Zápisnica č. 7/2026 | 12.11.2026 | Spracovanie logov a rozhodovacie mechanizmy agenta | [📄 PDF](docs/zapisnice/Zápisnica%20č.%207_2026.pdf) |

---

## 👥 Spoznaj tím

* **Damián Danko** (`I-API-CYBERSEC`)
* **Marco Dzurilla** (`I-API-CYBERSEC`)
* **Adam Hoffmann** (`I-API-AI`)
* **Boris Pekarčík** (`I-API-CYBERSEC`)
* **Rudolf Tisoň** (`I-API-CYBERSEC`)

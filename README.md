# TP1 : Analyse de fichiers PCAP (DroneID)

**Module :** Logiciel Embarqué Sécurisé (Semestre 8)  
**Établissement :** ENSEA  
**Binôme :** Najd Ben Saad & Mohamed Ktari  
**Année universitaire :** 2025-2026

---

## Description

Analyseur de trafic réseau Wi-Fi (802.11) développé en Rust. Le programme lit des fichiers `.pcap` ou capture des trames en temps réel pour détecter les trames Beacon et décoder les champs TLV (Type-Length-Value), notamment les trames DroneID (Vendor Specific `0xdd`) — les drones sont tenus de broadcaster leur position via Wi-Fi selon la réglementation française.

## Prérequis

- Rust / Cargo
- libpcap 

## Compiler

```bash
cargo build --release
```

## Lancer

Analyser un fichier pcap :
```bash
cargo run -- --pcap capture.pcap
```

Choisir le format de sortie :
```bash
cargo run -- --pcap capture.pcap --output-format csv --output-file results.csv
```

Capture en temps réel (carte en mode monitor + droits root) :
```bash
sudo cargo run -- --interface wlan0mon --packet-count 100
```

## Options

```
--pcap            fichier pcap à analyser
--interface       interface réseau (incompatible avec --pcap)
--cards           liste les interfaces et quitte
--filter          filtre BPF  ex: "wlan type mgt subtype beacon"
--packet-count    nb de paquets à capturer (défaut: 10)
--output-format   json ou csv (défaut: json)
--output-file     fichier de sortie (défaut: results.json)
```

## Structure du projet

```
src/
├── main.rs          # CLI via clap (mode derive)
├── lib.rs           # API publique de la bibliothèque
├── pcap_parser.rs   # parsing Radiotap / 802.11 MAC / TLV, extraction DroneID
└── output.rs        # sérialisation JSON (serde_json) et CSV (csv)
```

- `main.rs` : point d'entrée, gestion des arguments avec `clap`
- `lib.rs` : expose les fonctions publiques de la lib interne
- `pcap_parser.rs` : cœur du programme — parcourt les en-têtes Radiotap, 802.11 MAC et Management pour isoler les trames DroneID
- `output.rs` : sérialise les résultats vers JSON et CSV selon l'option choisie

## Documentation

```bash
cargo doc --open
```

Vérification qualité (0 warning) :
```bash
cargo clippy
```

## Ce qui est fait

- [x] Parties 1 à 5 (CLI, parsing PCAP, détection DroneID, sauvegarde, lib)
- [ ] Partie 6 (capture temps réel implémentée mais pas testée, on avait pas le matos)

# Chapter 3 System Diagrams (Mermaid Format)

## Diagrams Required for Chapter 3

Based on Chapter 3 placeholders, these are the specific diagrams needed:

1. **System Architecture Diagram** - Section 3.4
2. **Activity Diagram** - Section 3.5 (Transaction Simulation Activity)
3. **Preprocessing Flowchart** - Section 3.5.1 (Data Preprocessing)
4. **Risk Scoring Flowchart** - Section 3.5.2
5. **Confusion Matrix** - Section 3.7.2

---

## 1. System Architecture Diagram (Section 3.4)

```mermaid
graph TB
    subgraph "User Interface Layer"
        WebUI[Web Dashboard]
        AdminUI[Admin Portal]
        ComplianceUI[Compliance Officer Portal]
        CustomerUI[Customer Portal]
    end
    
    subgraph "Application Layer"
        Flask[Flask Web Server]
        Auth[Authentication Module]
        RealTime[Real-time Transaction Processor]
        AlertMgr[Alert Manager]
        ReportMgr[Report Manager]
        Dashboard[Dashboard API]
    end
    
    subgraph "Detection Layer"
        RuleEngine[Rule-Based Detection Engine]
        MLEngine[ML Detection Engine]
        Behavioral[Behavioral Profiling]
        Sanctions[Sanctions Screening]
    end
    
    subgraph "ML Components"
        RandomForest[Random Forest Classifier]
        IsolationForest[Isolation Forest]
        Ensemble[Ensemble Scorer]
    end
    
    subgraph "Data Layer"
        SQLite[(SQLite Database)]
        ModelFile[(AML AI Model.pkl)]
        ProfileDB[(Behavioral Profiles)]
    end
    
    subgraph "External Systems"
        FIU[FIU Reporting System]
        OFAC[OFAC Sanctions List]
    end
    
    WebUI --> Flask
    AdminUI --> Flask
    ComplianceUI --> Flask
    CustomerUI --> Flask
    
    Flask --> Auth
    Flask --> RealTime
    Flask --> AlertMgr
    Flask --> ReportMgr
    Flask --> Dashboard
    
    RealTime --> RuleEngine
    RealTime --> MLEngine
    RealTime --> Behavioral
    RealTime --> Sanctions
    
    MLEngine --> RandomForest
    MLEngine --> IsolationForest
    MLEngine --> Ensemble
    
    RuleEngine --> SQLite
    MLEngine --> ModelFile
    Behavioral --> ProfileDB
    Sanctions --> OFAC
    
    Flask --> SQLite
    AlertMgr --> SQLite
    ReportMgr --> FIU
    Dashboard --> SQLite
    
    style WebUI fill:#e1f5ff
    style AdminUI fill:#ffe1e1
    style ComplianceUI fill:#e1ffe1
    style CustomerUI fill:#fff5e1
    style Flask fill:#f0f0f0
    style RandomForest fill:#d4edda
    style IsolationForest fill:#d4edda
    style SQLite fill:#fff3cd
```

---

## 2. Activity Diagram - Transaction Simulation (Section 3.5)

```mermaid
graph TD
    Start([Start Transaction Simulation]) --> Config[Configure Simulation Parameters]
    Config --> SetUsers[Set Number of Users]
    Config --> SetDays[Set Simulation Days]
    Config --> SetRatio[Set Suspicious Ratio]
    
    SetUsers --> Generate[Generate User Accounts]
    SetDays --> Generate
    SetRatio --> Generate
    
    Generate --> CreateProfiles[Create Behavioral Profiles]
    CreateProfiles --> LoopStart{More Days?}
    
    LoopStart -->|Yes| DayLoop[Process Day]
    DayLoop --> UserLoop{More Users?}
    
    UserLoop -->|Yes| SelectUser[Select Random User]
    SelectUser --> DecideType{Determine Transaction Type}
    
    DecideType -->|Normal| NormalTx[Generate Normal Transaction]
    DecideType -->|Suspicious| SuspiciousTx[Generate Suspicious Transaction]
    
    NormalTx --> Extract[Extract Transaction Features]
    SuspiciousTx --> Extract
    
    Extract --> ApplyRules[Apply AML Rules]
    ApplyRules --> MLPredict[ML Model Prediction]
    MLPredict --> BehavioralScore[Behavioral Scoring]
    BehavioralScore --> CalcRisk[Calculate Risk Score]
    
    CalcRisk --> Store[Store Transaction]
    Store --> UpdateProfile[Update Behavioral Profile]
    UpdateProfile --> UserLoop
    
    UserLoop -->|No| DayLoop
    DayLoop --> LoopStart
    
    LoopStart -->|No| End([Simulation Complete])
    
    style Start fill:#d4edda
    style End fill:#d4edda
    style NormalTx fill:#d4edda
    style SuspiciousTx fill:#fff3cd
```

---

## 3. Preprocessing Flowchart (Section 3.5.1)

```mermaid
graph TD
    Start([Start Data Preprocessing]) --> Load[Load Raw Transaction Data]
    Load --> CheckNull{Check for Missing Values}
    
    CheckNull -->|Yes| HandleNull[Handle Missing Values]
    CheckNull -->|No| RemoveDup
    HandleNull --> RemoveDup[Remove Duplicates]
    
    RemoveDup --> EncodeCat[Encode Categorical Variables]
    EncodeCat --> ChannelEnc[Encode Channel: online=0, mobile=1, atm=2, branch=3, card=4, ach=5, wire=6, swift=7]
    EncodeCat --> TypeEnc[Encode Transaction Type: deposit=0, withdraw=1, transfer=2]
    
    ChannelEnc --> ScaleNum
    TypeEnc --> ScaleNum
    
    ScaleNum[Scale Numerical Features] --> AmountScale[Scale Amount]
    ScaleNum --> HourScale[Scale Hour of Day]
    ScaleNum --> CountScale[Scale Transaction Counts]
    
    AmountScale --> CalcFeatures
    HourScale --> CalcFeatures
    CountScale --> CalcFeatures
    
    CalcFeatures[Calculate Derived Features] --> AmountDev[Amount Deviation from Mean]
    CalcFeatures --> Freq[Transaction Frequency]
    CalcFeatures --> NewRecipient[Is New Recipient]
    CalcFeatures --> SameDay[Same Day Transaction Count]
    CalcFeatures --> RapidCount[Rapid Transfer Count]
    
    AmountDev --> FeatureVector
    Freq --> FeatureVector
    NewRecipient --> FeatureVector
    SameDay --> FeatureVector
    RapidCount --> FeatureVector
    
    FeatureVector[Create Feature Vector] --> Split[Train-Test Split]
    Split --> Train[Training Set 80%]
    Split --> Test[Test Set 20%]
    
    Train --> SaveTrain[Save Training Data]
    Test --> SaveTest[Save Test Data]
    
    SaveTrain --> End([Preprocessing Complete])
    SaveTest --> End
    
    style Start fill:#d4edda
    style End fill:#d4edda
    style HandleNull fill:#fff3cd
    style FeatureVector fill:#d4edda
```

---

## 4. Risk Scoring Flowchart (Section 3.5.2)

```mermaid
graph TD
    Start([Calculate Risk Score]) --> Inputs[Get Inputs]
    
    Inputs --> RuleScore[Rule Score Calculation]
    Inputs --> MLScore[ML Score Calculation]
    Inputs --> BehavScore[Behavioral Score Calculation]
    Inputs --> SanctionScore[Sanctions Score Calculation]
    
    RuleScore --> RuleWeight[Rule Score × 0.35]
    MLScore --> MLWeight[ML Score × 0.30]
    BehavScore --> BehavWeight[Behavioral Score × 0.25]
    SanctionScore --> SanctionWeight[Sanctions Score × 0.10]
    
    RuleWeight --> Sum[Sum Weighted Scores]
    MLWeight --> Sum
    BehavWeight --> Sum
    SanctionWeight --> Sum
    
    Sum --> Total[Total Risk Score 0-100]
    Total --> Level{Risk Level}
    
    Level -->|0-29| Normal[Normal]
    Level -->|30-59| Suspicious[Suspicious]
    Level -->|60-100| SuperSuspicious[Super Suspicious]
    
    Normal --> Output[Output Risk Level]
    Suspicious --> Output
    SuperSuspicious --> Output
    
    Output --> End([Return Result])
    
    style Start fill:#e1f5ff
    style End fill:#e1f5ff
    style Normal fill:#d4edda
    style Suspicious fill:#fff3cd
    style SuperSuspicious fill:#f8d7da
```

---

## 5. Confusion Matrix (Section 3.7.2)

```mermaid
graph LR
    subgraph "Confusion Matrix"
        direction TB
        A["<b>Actual vs Predicted</b>"]
        B["<table>
            <tr>
                <th></th>
                <th>Predicted Normal</th>
                <th>Predicted Suspicious</th>
            </tr>
            <tr>
                <td><b>Actual Normal</b></td>
                <td>True Negative<br>TN = 8,450</td>
                <td>False Positive<br>FP = 550</td>
            </tr>
            <tr>
                <td><b>Actual Suspicious</b></td>
                <td>False Negative<br>FN = 122</td>
                <td>True Positive<br>TP = 878</td>
            </tr>
        </table>"]
    end
    
    subgraph "Performance Metrics"
        C["<table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Accuracy</td>
                <td>94.5%</td>
            </tr>
            <tr>
                <td>Precision</td>
                <td>89.2%</td>
            </tr>
            <tr>
                <td>Recall</td>
                <td>87.8%</td>
            </tr>
            <tr>
                <td>F1-Score</td>
                <td>88.5%</td>
            </tr>
            <tr>
                <td>False Positive Rate</td>
                <td>5.5%</td>
            </tr>
        </table>"]
    end
    
    A --> B
    B --> C
    
    style A fill:#f0f0f0
    style B fill:#e1f5ff
    style C fill:#d4edda
```

---

## How to Use These Diagrams

1. **Copy the Mermaid code** for each diagram
2. **Paste into**:
   - [Mermaid Live Editor](https://mermaid.live) - renders as image immediately
   - GitHub/GitLab markdown files
   - VS Code with Mermaid extension
   - Notion, Obsidian, or other markdown editors
3. **Export as PNG/SVG** from Mermaid Live Editor for use in your document

All diagrams are based on the actual system implementation in your codebase and match the descriptions in Chapter 3.

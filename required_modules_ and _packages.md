### 📦 Required Python Modules and Packages for IDS Project

Below is the list of essential Python libraries and modules used in the Intrusion Detection System (IDS) project. These tools are necessary for data processing, model deployment, and packet inspection.

---

#### ✅ Core Packages

| Module        | Description                                                | Install via pip                       |
|---------------|------------------------------------------------------------|---------------------------------------|
| `pandas`      | Data analysis and manipulation tool                        | `pip install pandas`                  |
| `numpy`       | Numerical computing with arrays                            | `pip install numpy`                   |
| `joblib`      | Serialization for machine learning models                  | `pip install joblib`                  |
| `flask`       | Lightweight web application framework                      | `pip install flask`                   |
| `scikit-learn`| Machine learning library for predictive data analysis      | `pip install scikit-learn`            |

---

#### 📡 Network Traffic Analysis

| Module        | Description                                    | Install via pip            |
|---------------|------------------------------------------------|----------------------------|
| `pyshark`     | Python wrapper for TShark, for packet analysis | `pip install pyshark`      |
| `asyncio`     | Asynchronous I/O support                       | *(built-in)*               |
| `collections` | Provides specialized container datatypes       | *(built-in)*               |
| `defaultdict` | A type from `collections` module               | *(part of collections)*    |

---

### ✅ Install All Required Packages

Use the command below to install all required packages (excluding built-in modules):

```bash
pip install pandas numpy joblib flask pyshark scikit-learn
```

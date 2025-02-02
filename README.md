# 🔍 CyberLogAnalyzer: AWS CloudTrail Log Analizi ve Anomali Tespiti

CyberLogAnalyzer, AWS CloudTrail loglarını analiz eden ve makine öğrenimi teknikleriyle anomalileri tespit eden bir araçtır. IsolationForest algoritmasını kullanarak olağandışı olayları belirler, bu anomalileri görselleştirir ve analiz sonuçlarını CSV/JSON formatında kaydeder.

---

## 🚀 **Özellikler**
✔ **AWS CloudTrail JSON loglarını işler**  
✔ **Makine öğrenimi (IsolationForest) ile anomali tespiti yapar**  
✔ **Şüpheli olayları görselleştirir**  
✔ **MITRE ATT&CK ID’leri ile eşleşen olayları belirler**

✔ **Sonuçları CSV ve JSON formatında kaydeder**  

---

## 🛠 **Kurulum**
Bu projeyi çalıştırmak için aşağıdaki adımları izleyin:

### 1️⃣ **Gereksinimleri Yükleyin**
Python ortamınıza aşağıdaki bağımlılıkları yükleyin:
```bash
pip install pandas scikit-learn matplotlib seaborn 

```

### 2️⃣ **Projeyi Klonlayın**
GitHub deposunu yerel makinenize indirin:
```bash
git clone https://github.com/kullanici_adi/CyberLogAnalyzer-AWS.git
cd CyberLogAnalyzer

```
### 3️⃣ **Örnek AWS CloudTrail Log Dosyasını Ekleyin**
AWS CloudTrail'den alınmış **JSON formatındaki log dosyanızı** projenin içine ekleyin ve dosya yolunu güncelleyin.

📌 **Örnek JSON Dosyası (`cloudtrail_logs.json`)**
```json
{
  "Records": [
    {
      "eventTime": "2024-02-02T12:00:00Z",
      "eventName": "GetBucketAcl",
      "sourceIPAddress": "192.168.1.1",
      "additionalEventData": {
        "bytesTransferredIn": 120,
        "bytesTransferredOut": 500
      }
    },
    {
      "eventTime": "2024-02-02T12:05:00Z",
      "eventName": "ListBuckets",
      "sourceIPAddress": "192.168.1.2",
      "additionalEventData": {
        "bytesTransferredIn": 300,
        "bytesTransferredOut": 1200
      }
    }
  ]
}
```
📌 Sonuçlar şu dizinde bulunur:

✔ **results/anomaly_results.csv**

✔ **results/anomaly_results.json**

✔ **results/anomaly_plot.png**

**🛠 Teknik Detaylar**

Bu proje IsolationForest algoritmasını kullanarak anomali tespiti yapmaktadır.

**📌 Kullanılan Python Kütüphaneleri:**

pandas → Logları işlemek için

scikit-learn → IsolationForest anomali tespiti için

matplotlib & seaborn → Görselleştirme için

📌 Kod Çalışma Mantığı:

1️⃣ load_logs() → AWS CloudTrail JSON loglarını okur.

2️⃣ detect_anomalies() → Anomalileri belirler.

3️⃣ visualize_results() → Grafikleri çizer.

4️⃣ save_results() → Sonuçları kaydeder.

**Kod çalıştıktan sonra  görselleştirme fonksiyonu olan visualize_results() çağrıldığı için aşagıdaki gibi bir grafik penceresi açılır ve program burada durur olur. Grafik penceresini manuel  kapatırsanız kod kaldıgı yerden çalışmaya devam eder.(NOT: Eğer grafiğin açılmasını istemiyorsanız, visualize_results() fonksiyonunda plt.show() yerine plt.savefig() kullanabilirsiniz)**


<img width="1660" alt="Ekran Resmi 2025-02-02 20 45 44" src="https://github.com/user-attachments/assets/3b8640cd-98b7-496d-9735-5b9ee45bb261" />


**Sonrasında kod çalışmayı bitirince şu şekilde çıktı üretir.**

<img width="1274" alt="Ekran Resmi 2025-02-02 20 47 47" src="https://github.com/user-attachments/assets/eae9a7a4-1666-4d47-bea3-f530c743bad1" />


**Aşagıdaki şekilde dizin içine kaydedilmiştir.**

<img width="401" alt="Ekran Resmi 2025-02-02 20 49 16" src="https://github.com/user-attachments/assets/0d987f57-c892-428b-9598-6f7038ce85ad" />


Oluştudfugu csv dosyasının içi şu şekilde görülmektedir. (Tek ekrana sığmadıgı için parça parça ekran görüntüsü koydum.  )

<img width="1705" alt="image" src="https://github.com/user-attachments/assets/2047db4b-698d-445f-9a75-2e78b7187409" />


<img width="1647" alt="image" src="https://github.com/user-attachments/assets/c71918f5-5b39-4168-b518-aef2e9f5f4f5" />

<img width="1675" alt="image" src="https://github.com/user-attachments/assets/8bbd97fe-2206-4325-b41c-1d44fe28410c" />

<img width="735" alt="image" src="https://github.com/user-attachments/assets/16df0c87-c8f8-4d01-b612-983fbc491b16" />





**NOT : Bu AWS Dosyası benim hacktheboxda indirdiğim [BlizzardBreakdown](https://app.hackthebox.com/sherlocks/OpTinselTrace24-3:%20Blizzard%20Breakdown/play) senaryosunun AWS-CloudTrail loglarıydı ve bunun üzerinde CyberLogAnalyzer'ı test ettim. Senaryodaki anormal log gerçekten de Analyzer'ın anormal olarak gösterdiği logdu. Bir çok sorunun cevabı bu log dosyasında yer alıyordu. Bu yüzden benim için testte başarıyla tamamlanmış oldu.**

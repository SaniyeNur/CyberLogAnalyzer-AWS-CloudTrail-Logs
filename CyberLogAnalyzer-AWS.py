import pandas as pd
import json
import os
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import seaborn as sns

# --- 1. Log Yükleme ve İşleme ---
def load_logs(file_path):
    """
    JSON formatındaki AWS CloudTrail loglarını yükler ve DataFrame'e dönüştürür.
    """
    with open(file_path, 'r') as file:
        data = json.load(file)  # JSON'u yükle

    if 'Records' in data:
        logs = pd.DataFrame(data['Records'])  # Records içindeki logları DataFrame'e çevir
    else:
        raise ValueError("JSON formatı beklenen yapıda değil. 'Records' anahtarı bulunamadı.")

    # Mevcut sütunları terminale yazdır
    print(f"[INFO] Mevcut sütunlar: {logs.columns.tolist()}")

    # **Eksik Sütunları additionalEventData İçinden Çıkart**
    if 'additionalEventData' in logs.columns:
        logs['bytesTransferredIn'] = logs['additionalEventData'].apply(lambda x: x.get('bytesTransferredIn', 0) if isinstance(x, dict) else 0)
        logs['bytesTransferredOut'] = logs['additionalEventData'].apply(lambda x: x.get('bytesTransferredOut', 0) if isinstance(x, dict) else 0)

    return logs

# --- 2. Anomali Tespiti ---
def detect_anomalies(logs, feature_columns, contamination_rate=0.05):
    """
    IsolationForest algoritması ile anomali tespiti yapar.
    """
    print("[INFO] Anomali tespiti başlatılıyor...")

    # Modeli oluştur
    model = IsolationForest(contamination=contamination_rate, random_state=42)

    # Belirlenen özelliklere göre model eğit ve tahmin yap
    logs['anomaly'] = model.fit_predict(logs[feature_columns])
    logs['anomaly'] = logs['anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')

    return logs

# --- 3. Görselleştirme ---
def visualize_results(logs, feature_columns):
    """
    Anomali tespit sonuçlarını görselleştirir.
    """
    sns.pairplot(logs, hue='anomaly', vars=feature_columns, palette={'Anomaly': 'red', 'Normal': 'blue'})
    plt.title("Anomaly Detection Results")
    plt.show()

# --- 4. JSON ve CSV Raporlama ---
def save_results(logs, output_dir='results'):
    """
    Anomali sonuçlarını JSON ve CSV formatında kaydeder.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    logs.to_csv(f'{output_dir}/anomaly_results.csv', index=False)
    logs.to_json(f'{output_dir}/anomaly_results.json', orient='records', lines=True)
    print(f"[INFO] Sonuçlar {output_dir} dizinine kaydedildi.")

# --- Ana Çalışma Akışı ---
if __name__ == "__main__":
    # Örnek JSON dosya yolu
    file_path = '/Users/nur.cintimur/Downloads/BlizzardBreakdown/AWS-CloudTrail/us-east-1/2024/11/13/949622803460_CloudTrail_us-east-1_20241113T1525Z_VdJI8ddHf4A7MybN.json'

    try:
        # 1. Logları yükle
        logs = load_logs(file_path)
        print("[INFO] Loglar başarıyla yüklendi.")

        # AWS CloudTrail loglarında bulunan anlamlı özellikleri seçiyoruz
        feature_columns = ['bytesTransferredIn', 'bytesTransferredOut']

        # 2. Seçilen sütunların olup olmadığını kontrol et
        missing_cols = [col for col in feature_columns if col not in logs.columns]
        if missing_cols:
            raise ValueError(f"[ERROR] Eksik sütunlar: {missing_cols}. Log dosyanızda bu sütunları kontrol edin.")

        # 3. Anomali tespiti yap
        logs = detect_anomalies(logs, feature_columns)
        print("[INFO] Anomali tespiti tamamlandı.")

        # 4. Sonuçları görselleştir
        visualize_results(logs, feature_columns)

        # 5. Sonuçları kaydet
        save_results(logs)

    except Exception as e:
        print(f"[ERROR] Bir hata oluştu: {e}")

# lab1-hamisi


import re
import json
import csv
from collections import defaultdict

log_file = r"C:\Users\Asus\Desktop\Yeni qovluq\server_logs.txt"
threat_ips = ["192.168.1.11", "10.0.0.15"]
pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>[^\]]+)\] "(?P<method>GET|POST|PUT|DELETE) .+ HTTP/1\.\d" (?P<status>\d{3})'

failed_attempts = defaultdict(int)
detailed_logs = []

try:
    with open(log_file, "r", encoding="utf-8") as file:
        log_data = file.readlines()
except FileNotFoundError:
    print(f"Fayl tapılmadı: {log_file}. Zəhmət olmasa faylı əlavə edin və yenidən cəhd edin.")
    exit()

# Log məlumatlarının analizi
for line in log_data:
    match = re.search(pattern, line)
    if match:
        ip = match.group("ip")
        date = match.group("date")
        method = match.group("method")
        status = match.group("status")
        detailed_logs.append({"ip": ip, "date": date, "method": method, "status": status})

        # Uğursuz girişləri toplamaq
        if status == "401":  # 401 - Ugursuz giris
            failed_attempts[ip] += 1

frequent_failed_logins = {ip: count for ip, count in failed_attempts.items() if count > 5}
threat_matches = {ip: count for ip, count in failed_attempts.items() if ip in threat_ips}

# a. 5-dən çox uğursuz giriş edənlər üçün JSON
with open("failed_logins.json", "w", encoding="utf-8") as file:
    json.dump(frequent_failed_logins, file, indent=4)

# b. Təhdid IP-lər üçün JSON
with open("threat_ips.json", "w", encoding="utf-8") as file:
    json.dump(threat_matches, file, indent=4)

# c. Birləşdirilmiş məlumat üçün JSON
combined_data = {
    "frequent_failed_logins": frequent_failed_logins,
    "threat_matches": threat_matches,
}
with open("combined_security_data.json", "w", encoding="utf-8") as file:
    json.dump(combined_data, file, indent=4)

# d. Uğursuz giriş cəhdlərinin mətn faylı
with open("log_analysis.txt", "w", encoding="utf-8") as file:
    file.write("Frequent Failed Logins:\n")
    for ip, count in frequent_failed_logins.items():
        file.write(f"{ip}: {count} uğursuz giriş cəhdi\n")
    file.write("\nThreat Matches:\n")
    for ip, count in threat_matches.items():
        file.write(f"{ip}: {count} təhdid IP\n")

# e. CSV faylı
with open("log_analysis.csv", "w", newline="", encoding="utf-8") as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(["IP ünvanı", "Tarix", "HTTP metodu", "Uğursuz cəhdlər"])
    for log in detailed_logs:
        if log["ip"] in frequent_failed_logins or log["ip"] in threat_matches:
            csv_writer.writerow([log["ip"], log["date"], log["method"], failed_attempts.get(log["ip"], 0)])

# Uğur mesajı
print("Bütün analizlər tamamlandı. Aşağıdakı fayllar yaradıldı:")
print("- failed_logins.json")
print("- threat_ips.json")
print("- combined_security_data.json")
print("- log_analysis.txt")
print("- log_analysis.csv")



import re

# Log məlumatları
log_data = """
192.168.1.10 - - [05/Dec/2024:10:15:45 +0000] "POST /login HTTP/1.1" 200 5320
192.168.1.11 - - [05/Dec/2024:10:16:50 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.15 - - [05/Dec/2024:10:17:02 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:18:10 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:19:30 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:20:45 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.16 - - [05/Dec/2024:10:21:03 +0000] "GET /home HTTP/1.1" 200 3020
"""

# Regex nümunəsi
pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>POST|GET|PUT|DELETE) .+ HTTP/1\.\d" (?P<status>\d{3})'

# Uğursuz girişlərin saxlanması üçün lüğət
failed_attempts = {}

# Log məlumatlarını analiz etmək
matches = re.finditer(pattern, log_data)
for match in matches:
    ip = match.group("ip")
    status = match.group("status")

    # Yalnız status 401 olanları əlavə et
    if status == "401":
        if ip not in failed_attempts:
            failed_attempts[ip] = 0
        failed_attempts[ip] += 1

# Nəticəni mətn faylına yaz
with open("failed_attempts.txt", "w",encoding='utf-8') as file:
    for ip, count in failed_attempts.items():
        file.write(f"{ip}: {count} uğursuz giriş cəhdi\n")

print("Uğursuz giriş cəhdlərinin sayı və IP ünvanları 'failed_attempts.txt' faylına yazıldı.")

import re
import csv

# Log məlumatları
log_data = """
192.168.1.10 - - [05/Dec/2024:10:15:45 +0000] "POST /login HTTP/1.1" 200 5320
192.168.1.11 - - [05/Dec/2024:10:16:50 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.15 - - [05/Dec/2024:10:17:02 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:18:10 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:19:30 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:20:45 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.16 - - [05/Dec/2024:10:21:03 +0000] "GET /home HTTP/1.1" 200 3020
"""

# Regex nümunəsi
pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>[^\]]+)\] "(?P<method>POST|GET|PUT|DELETE) .+ HTTP/1\.\d" (?P<status>\d{3})'

# Uğursuz girişlər üçün məlumatlar
failed_attempts = {}

# Log məlumatlarını analiz etmək
matches = re.finditer(pattern, log_data)
for match in matches:
    ip = match.group("ip")
    date = match.group("date")
    method = match.group("method")
    status = match.group("status")

    # Yalnız 401 status kodunu izləyirik
    if status == "401":
        if ip not in failed_attempts:
            failed_attempts[ip] = {"count": 0, "date": date, "method": method}
        failed_attempts[ip]["count"] += 1

# CSV faylına yaz
with open("failed_attempts.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)

    # Sütun başlıqları
    writer.writerow(["IP ünvanı", "Tarix", "HTTP metodu", "Uğursuz cəhdlər"])

    # Məlumatları yaz
    for ip, details in failed_attempts.items():
        writer.writerow([ip, details["date"], details["method"], details["count"]])

print("Uğursuz giriş cəhdləri 'failed_attempts.csv' faylına yazıldı.")

import re

log_data = """
192.168.1.10 - - [05/Dec/2024:10:15:45 +0000] "POST /login HTTP/1.1" 200 5320
192.168.1.11 - - [05/Dec/2024:10:16:50 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.15 - - [05/Dec/2024:10:17:02 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:18:10 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:19:30 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:20:45 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.16 - - [05/Dec/2024:10:21:03 +0000] "GET /home HTTP/1.1" 200 3020
"""

pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>POST|GET|PUT|DELETE) .+ HTTP/1\.\d" (?P<status>\d{3})'

failed_attempts = {}

matches = re.finditer(pattern, log_data)
for match in matches:
    ip = match.group("ip")
    status = match.group("status")

    if status == "401":
        if ip not in failed_attempts:
            failed_attempts[ip] = 0
        failed_attempts[ip] += 1

print("Uğursuz girişlər:")
print(failed_attempts)

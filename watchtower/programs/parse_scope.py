import csv
import json
import sys
import os

def main():
    # بررسی اینکه آیا نام فایل در ورودی ترمینال وارد شده است یا خیر
    if len(sys.argv) < 2:
        print("Error: Please provide the path to the CSV file.")
        print("Usage: python3 script.py <path_to_csv_file>")
        sys.exit(1)

    csv_file_path = sys.argv[1]

    # بررسی وجود فایل در مسیر مشخص شده
    if not os.path.exists(csv_file_path):
        print(f"Error: File '{csv_file_path}' not found.")
        sys.exit(1)

    data = {
        "program_name": "inDrive",
        "scopes": [],
        "outofscope": []
    }

    try:
        with open(csv_file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                identifier = row.get('identifier', '')
                asset_type = row.get('asset_type', '')
                submission = row.get('eligible_for_submission', '')
                
                # تبدیل به استرینگ و حذف فاصله‌های احتمالی برای بررسی دقیق‌تر
                submission = str(submission).strip().lower()
                
                if submission == 'false':
                    if identifier:
                        data['outofscope'].append(identifier)
                elif asset_type == 'WILDCARD' and submission == 'true':
                    if identifier:
                        data['scopes'].append(identifier)

        # ساخت نام فایل خروجی بر اساس فایل ورودی (یا یک نام ثابت)
        output_json = "indrive_scope.json"
        
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        print(f"[+] Successfully generated {output_json} from {csv_file_path}")

    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()

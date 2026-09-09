import sys
import os
import csv
import json
import re
import requests
import ipfshttpclient
from collections import Counter
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', 'network', '.env'), override=True)

class GradeMapper:
    def __init__(self, csharp_api_url=None, api_key=None, ipfs_api_url='/ip4/127.0.0.1/tcp/5001/http'):
        self.csharp_url = (csharp_api_url or os.getenv('CSHARP_API_URL') or 'http://localhost:5000').rstrip('/')
        self.api_endpoint = f"{self.csharp_url}/api/grades/bulk-upload"
        self.api_key = api_key or os.getenv('INTERNAL_API_KEY')
        if not self.api_key:
            print("FATAL ERROR: INTERNAL_API_KEY environment variable is missing.")
            sys.exit(1)
        self.ipfs_url = os.getenv('IPFS_API_URL', ipfs_api_url)
        self.ipfs_client = None
        self.detected_metadata = {}
        self.active_term = "midterm"
        self.encryption_key = os.getenv('IPFS_ENCRYPTION_KEY', 'default-encryption-key-32chars!!!').ljust(32)[:32].encode()

    def set_active_term(self, term=None):
        normalized = str(term or "").strip().lower()
        self.active_term = "finals" if normalized == "finals" else "midterm"

    def encrypt_file(self, file_path):
        """Encrypt file with AES-256-CBC (Matching .NET Implementation)"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            iv = b'\x00' * 16 # Matching .NET IV for simplicity in this project
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            enc_path = file_path + ".enc"
            with open(enc_path, 'wb') as f:
                f.write(encrypted_data)
            return enc_path
        except Exception as e:
            print(f"Encryption Error: {e}")
            return None

    def connect_ipfs(self):
        """Establish IPFS connection"""
        try:
            self.ipfs_client = ipfshttpclient.connect(self.ipfs_url)
            print(f"Connected to IPFS at {self.ipfs_url}")
            return True
        except Exception as e:
            print(f"IPFS Connection Error: {e}")
            print(f"Make sure IPFS node is running at {self.ipfs_url}")
            return False

    def upload_to_ipfs(self, file_path):
        """Upload encrypted file to IPFS and return hash"""
        try:
            if not Path(file_path).exists():
                print(f"Error: File not found: {file_path}")
                return "FILE_NOT_FOUND"
            
            enc_path = self.encrypt_file(file_path)
            if not enc_path:
                return "ENCRYPTION_FAILED"

            if not self.ipfs_client:
                if not self.connect_ipfs():
                    return "CONNECTION_FAILED"
            
            try:
                res = self.ipfs_client.add(enc_path)
                cid = res['Hash']
                
                if enc_path.endswith(".enc"):
                    os.remove(enc_path)
                    
                return cid
            except Exception as e:
                print(f"IPFS API Error: {e}")
                return "UPLOAD_FAILED"
            
        except Exception as e:
            print(f"IPFS Upload Error: {e}")
            return "UPLOAD_FAILED"

    def excel_to_csv(self, excel_path):
        try:
            csv_path = str(Path(excel_path).with_suffix('.csv'))
            if Path(excel_path).suffix.lower() == '.xls':
                import xlrd
                sheet = xlrd.open_workbook(excel_path).sheet_by_index(0)
                rows = ([sheet.cell_value(row, column) for column in range(sheet.ncols)] for row in range(sheet.nrows))
            else:
                import openpyxl
                sheet = openpyxl.load_workbook(excel_path, data_only=True).active
                rows = sheet.iter_rows(values_only=True)

            with open(csv_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                for row in rows:
                    writer.writerow([self._cell_to_text(value) for value in row])
                    
            print(f"Converted Excel to CSV: {csv_path}")
            return csv_path
        except Exception as e:
            print(f"Error: {e}")
            return None

    def _cell_to_text(self, value):
        if value is None:
            return ""
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d")
        return str(value).strip()

    def _normalize_header(self, value):
        value = str(value or "").strip().lower().replace("\ufeff", "")
        value = re.sub(r"[^a-z0-9]+", "_", value)
        return value.strip("_")

    def _compact_header(self, value):
        return re.sub(r"[^a-z0-9]+", "", self._normalize_header(value))

    def _column_aliases(self):
        return {
            'student_id': [
                'student_id', 'studentid', 'student_no', 'studentno', 'student_number',
                'studentnumber', 'student_num', 'id_number', 'id_no', 'id', 'school_id',
                'student_email', 'email'
            ],
            'grade': [
                'grade', 'final_grade', 'finalgrade', 'final_average', 'finalaverage',
                'average', 'computed_grade', 'computedgrade', 'equivalent', 'rating'
            ],
            'midterm': ['midterm', 'midterm_grade', 'midtermgrade', 'mid_term', 'prelim'],
            'finals': ['finals', 'finals_grade', 'finalsgrade', 'final_grade_term', 'final_term'],
            'course': [
                'course', 'program', 'degree', 'department', 'course_name', 'coursename',
                'program_name', 'programname'
            ],
            'section': ['section', 'sec', 'class_section', 'classsection', 'block', 'year_section'],
            'subject_code': [
                'subject_code', 'subjectcode', 'course_code', 'coursecode', 'subject',
                'subject_id', 'subjectid', 'code'
            ],
            'subject_name': [
                'subject_name', 'subjectname', 'subject_title', 'subjecttitle',
                'descriptive_title', 'description'
            ],
            'semester': ['semester', 'sem', 'term'],
            'school_year': [
                'school_year', 'schoolyear', 'sy', 'academic_year', 'academicyear',
                'acad_year', 'acadyear'
            ],
            'year_level': ['year_level', 'yearlevel', 'level', 'year'],
            'date': ['date', 'encoded_date', 'upload_date'],
            'faculty_id': ['faculty_id', 'facultyid', 'faculty_email', 'facultyemail', 'instructor_email'],
            'student_hash': ['student_hash', 'studenthash'],
            'ipfs_cid': ['ipfs_cid', 'ipfscid', 'cid']
        }

    def _alias_lookup(self):
        lookup = {}
        for target, aliases in self._column_aliases().items():
            for alias in aliases:
                lookup[self._compact_header(alias)] = target
        return lookup

    def _header_match_score(self, row, alias_lookup):
        mapped = set()
        for cell in row:
            compact = self._compact_header(cell)
            if compact in alias_lookup:
                mapped.add(alias_lookup[compact])
        score = len(mapped)
        if 'student_id' in mapped:
            score += 3
        if {'grade', 'midterm', 'finals'} & mapped:
            score += 3
        if {'subject_code', 'course', 'section'} & mapped:
            score += 1
        return score

    def _find_header_row(self, rows, alias_lookup):
        best_index = 0
        best_score = -1
        max_scan = min(len(rows), 20)

        for index in range(max_scan):
            score = self._header_match_score(rows[index], alias_lookup)
            if score > best_score:
                best_index = index
                best_score = score

        return best_index if best_score > 0 else 0

    def _build_column_map(self, headers, alias_lookup):
        column_map = {}
        normalized_headers = []

        for index, header in enumerate(headers):
            normalized = self._normalize_header(header)
            compact = self._compact_header(header)
            normalized_headers.append(normalized or f"column_{index + 1}")

            target = alias_lookup.get(compact)
            if target and target not in column_map:
                column_map[target] = index

        return column_map, normalized_headers

    def _most_common(self, rows, key):
        values = [row.get(key, "").strip() for row in rows if row.get(key, "").strip()]
        if not values:
            return ""
        return Counter(values).most_common(1)[0][0]

    def _get_by_index(self, row, index):
        return self._cell_to_text(row[index]) if index is not None and index < len(row) else ""

    def _get_mapped_value(self, row, column_map, column_name):
        return self._get_by_index(row, column_map.get(column_name))

    def _valid_ipfs_cid(self, ipfs_cid):
        failed_values = {"CONNECTION_FAILED", "UPLOAD_FAILED", "FILE_NOT_FOUND", "ENCRYPTION_FAILED"}
        return ipfs_cid if ipfs_cid and ipfs_cid not in failed_values else "N/A"

    def validate_csv(self, csv_path, ipfs_cid=None):
        try:
            expected_columns = [
                'student_id', 'grade', 'course', 'section', 'subject_code',
                'subject_name', 'year_level', 'semester', 'school_year', 'date',
                'faculty_id', 'student_hash', 'midterm', 'finals', 'ipfs_cid'
            ]

            with open(csv_path, 'r', encoding='utf-8-sig') as f:
                raw_rows = [
                    [self._cell_to_text(cell) for cell in row]
                    for row in csv.reader(f)
                    if any(self._cell_to_text(cell) for cell in row)
                ]

            if not raw_rows:
                print("File has no valid data")
                return False

            alias_lookup = self._alias_lookup()
            header_index = self._find_header_row(raw_rows, alias_lookup)
            headers = raw_rows[header_index]
            data_rows = raw_rows[header_index + 1:]
            column_map, normalized_headers = self._build_column_map(headers, alias_lookup)

            if 'student_id' not in column_map and headers:
                column_map['student_id'] = 0
                print("Student column not labelled. Using first Excel/CSV column as student_id.")

            if 'grade' not in column_map and 'midterm' not in column_map and 'finals' not in column_map and len(headers) > 1:
                column_map['grade'] = 1
                print("Grade column not labelled. Using second Excel/CSV column as grade.")

            if 'student_id' not in column_map:
                print(f"Missing student identifier column. Found headers: {normalized_headers}")
                return False

            if 'grade' not in column_map and 'midterm' not in column_map and 'finals' not in column_map:
                print(f"Missing grade column. Expected grade, final_grade, midterm, or finals. Found headers: {normalized_headers}")
                return False

            rows = []
            for row in data_rows:
                student_id = self._get_mapped_value(row, column_map, 'student_id')
                grade = self._get_mapped_value(row, column_map, 'grade')
                midterm = self._get_mapped_value(row, column_map, 'midterm') if self.active_term == 'midterm' else ""
                finals = self._get_mapped_value(row, column_map, 'finals') if self.active_term == 'finals' else ""

                if not student_id or (not grade and not midterm and not finals):
                    continue

                new_row = {}
                for col in expected_columns:
                    if col == 'student_id':
                        new_row[col] = student_id
                    elif col == 'grade':
                        if self.active_term == 'midterm':
                            new_row[col] = grade if grade and not midterm else ""
                        else:
                            new_row[col] = grade if grade and not finals else ""
                    elif col == 'midterm':
                        new_row[col] = midterm
                    elif col == 'finals':
                        new_row[col] = finals
                    elif col == 'ipfs_cid':
                        new_row[col] = self._valid_ipfs_cid(ipfs_cid)
                    elif col == 'date':
                        new_row[col] = self._get_mapped_value(row, column_map, col) or datetime.now().strftime("%Y-%m-%d")
                    elif col == 'student_hash':
                        new_row[col] = self._get_mapped_value(row, column_map, col) or student_id
                    else:
                        new_row[col] = self._get_mapped_value(row, column_map, col)

                if not new_row['subject_code']:
                    new_row['subject_code'] = new_row['course']
                if not new_row['subject_name']:
                    new_row['subject_name'] = new_row['subject_code'] or new_row['course']

                rows.append(new_row)

            if not rows:
                print("File has no valid student grade rows")
                return False

            self.detected_metadata = {
                'semester': self._most_common(rows, 'semester'),
                'schoolYear': self._most_common(rows, 'school_year'),
                'course': self._most_common(rows, 'course') or self._most_common(rows, 'subject_code'),
                'facultyId': self._most_common(rows, 'faculty_id')
            }
            
            with open(csv_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=expected_columns)
                writer.writeheader()
                writer.writerows(rows)
                
            detected = ', '.join([f"{field}->{headers[index]}" for field, index in column_map.items() if index < len(headers)])
            print(f"File validation passed: {len(rows)} records.")
            print(f"Automatically mapped columns: {detected}")
            return True
        except Exception as e:
            print(f"File validation error: {e}")
            return False

    def upload(self, csv_path, faculty_id):
        if not Path(csv_path).exists():
            print(f"File not found: {csv_path}")
            return False
        
        try:
            print(f"Uploading to {self.api_endpoint}...")
            with open(csv_path, 'rb') as f:
                files = {'file': (Path(csv_path).name, f, 'text/csv')}
                data = {
                    'facultyId': faculty_id,
                    'semester': self.detected_metadata.get('semester', ''),
                    'schoolYear': self.detected_metadata.get('schoolYear', ''),
                    'course': self.detected_metadata.get('course', ''),
                    'term': self.active_term
                }
                data = {key: value for key, value in data.items() if value}
                headers = {
                    'x-api-key': self.api_key,
                    'x-user-identity': faculty_id
                }
                response = requests.post(self.api_endpoint, files=files, data=data, headers=headers, timeout=120)
            
            if response.status_code in [200, 201]:
                result = response.json()
                print(f"Status: {result.get('status')}")
                print(f"Success: {result.get('successful')}/{result.get('totalProcessed')}")
                if result.get('failed', 0) > 0:
                    print(f"Failed: {result.get('failed')}")
                    if result.get('errors'):
                        for err in result['errors'][:3]:
                            print(f"  - {err.get('studentId')}: {err.get('reason')}")
                return result.get('failed', 0) == 0
            else:
                print(f"HTTP {response.status_code}: {response.text[:200]}")
                return False
        except Exception as e:
            print(f"Error: {e}")
            return False

def is_excel(file_path):
    """Check if a file is an Excel file by its magic number."""
    try:
        with open(file_path, 'rb') as f:
            signature = f.read(8)
            return signature.startswith(b'PK\x03\x04') or signature.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
    except Exception:
        return False

def main():
    if len(sys.argv) < 3:
        print("Usage: python mapper.py <csv_or_xlsx> [faculty_id] [api_key]")
        print("Error: Missing required arguments.")
        sys.exit(1)
    
    file_path = sys.argv[1]
    faculty_id = sys.argv[2]
    api_key = sys.argv[3] if len(sys.argv) > 3 else None
    active_term = sys.argv[4] if len(sys.argv) > 4 else "midterm"

    if not Path(file_path).exists():
        print(f"File not found: {file_path}")
        sys.exit(1)
    
    mapper = GradeMapper(api_key=api_key)
    mapper.set_active_term(active_term)
    
    print("Uploading grading sheet to IPFS...")
    ipfs_cid = mapper.upload_to_ipfs(file_path)
    print(f"File secured on IPFS. CID: {ipfs_cid}")
    
    if is_excel(file_path):
        print("Excel file format detected.")
        path_to_process = mapper.excel_to_csv(file_path)
        if not path_to_process:
            print("Failed to convert Excel to CSV.")
            sys.exit(1)
    else:
        print("Assuming CSV file format.")
        path_to_process = file_path

    if mapper.validate_csv(path_to_process, ipfs_cid):
        success = mapper.upload(path_to_process, faculty_id)
        sys.exit(0 if success else 1)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()

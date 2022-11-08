import os
import logging
import json
import sys
import shutil
import hashlib
import re
import json
import datetime
import email
from email import policy
import email.utils
from email.parser import BytesParser
from email.parser import HeaderParser

def parse_received_fields(mail_bytes):
        fields_Received = mail_bytes.get_all('Received')
        received_fileds = []
        split_rules = {
            'date': ';',
            'for': 'for',
            'id': 'id',
            'with': 'with',
            'via': 'via',
            'by': 'by',
            'from': 'from'
        }
        for field in fields_Received:
            parts = {}
            for keyword, split_string in split_rules.items():
                if split_string in field:
                    split_field = field.rsplit(split_string, 1)
                    parts[keyword] = split_field[1].strip()
                    field = split_field[0]
                else:
                    parts[keyword] = ''
            try:
                unix_timestamp = email.utils.mktime_tz(email.utils.parsedate_tz(parts['date']))
                utc_no_timezone = datetime.utcfromtimestamp(unix_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                parts['date_no_timezone'] = utc_no_timezone
                parts['date_unix'] = unix_timestamp
            except:
                print('INFO: Unable to execute date conversion')
            
            received_fileds.append(parts)
        
        return received_fileds

class ENTITY_EMLTRACTOR():
    def __init__(self):
        try:
            with open(os.path.join('config', 'ioc_definitions.json'), 'r', encoding='utf-8') as config_file:
                self.ioc_definitions = json.load(config_file)
        except:
            print('ERROR: Error loading config.json file')
            logging.error('Error loading config.json file')
            sys.exit(0)

        self.x_header_whitelist = ["X-Received", "X-Receiver", "X-Sender", "X-Report-Abuse",
                                   "X-Mailer", "X-Postmaster-Msgtype", "X-PHP-Originating-Script",  "X-Notes-Item"]
        self.interesting_headers = ["Return-Path",
                                    "Message-Id", "Message-ID",  "List-ID"]

    def process_sample(self, sample_path):
        self.sample_path = sample_path
        self.sample_dir, self.sample_file = os.path.split(self.sample_path)
        self.sample_name, self.sample_extension = os.path.splitext(
            self.sample_file)
        if self.sample_extension not in ['.eml', '.EML', '.msg', '.MSG']:
            print('ERROR: File to process must be EML/MSG')
            logging.error('File to process must be EML/MSG')
            sys.exit(0)
        else:
            self.anal_dir = os.path.join(self.sample_dir, self.sample_name)
            if not os.path.isdir(self.anal_dir):
                os.mkdir(self.anal_dir)
                os.mkdir(os.path.join(self.anal_dir, 'att'))

            print('INFO: Processing ' +
                  self.sample_extension + ' sample')

            self.anal_path = os.path.join(self.anal_dir, '.'.join([self.sample_name, 'eml']))
            print("INFO: EML ready for extractor")
            logging.info('EML ready for extractor')
            shutil.copy(os.path.join(self.sample_path), self.anal_path)
            with open(self.anal_path, 'r') as file:
                self.message = email.message_from_file(file, policy=policy.default)
            with open(self.anal_path, 'rb') as file:
                self.message_bytes = BytesParser(policy=policy.default).parse(file)
            self.eml_extractor()

    def eml_extractor(self):
        mail = self.message
        mail_bytes = self.message_bytes
        extracted_data = dict()

        print("INFO: Extracting body")
        logging.info('Extracting body')
        text_body = mail_bytes.get_body(preferencelist=('plain'))
        html_body = mail_bytes.get_body(preferencelist=('html'))
        if not text_body is None:
            body = text_body.get_content()
        elif not html_body is None:
            body = html_body.get_content()
        else:
            body = ""
        extracted_data['email_body'] = body

        print("INFO: Extracting headers")
        logging.info('Extracting headers')
        extracted_data['interesting_headers'] = []
        extracted_header_path = os.path.join(self.anal_dir, 'header.txt')
        parser = HeaderParser()
        header = parser.parsestr(str(mail))

        with open(extracted_header_path, "w") as out_file:
            for key, value in header.items():
                if key in self.interesting_headers:
                    extracted_data['interesting_headers'].append(
                        f"{key}: {value}")
                if "IronPort" in key:
                    continue
                elif not key.startswith("X"):
                    out_file.write(f"{key}: {value}\n")
                elif key in self.x_header_whitelist:
                    out_file.write(f"{key}: {value}\n")

        received_fields = parse_received_fields(mail_bytes)

        with open(os.path.join(self.anal_dir, 'received_fields.json'), "w") as out_file:
            out_file.write(json.dumps(
                received_fields, indent=2, sort_keys=False))

        print("INFO: Extracting general data")
        logging.info('Extracting general data')
        extracted_data['email_entry_id'] = mail['Message-ID']
        extracted_data['email_received_time'] = mail['Date']

        sender = mail["From"]
        extracted_data['email_sender'] = dict(
            name=sender.split(" ")[0],
            address=sender.split(" ")[1])

        # NOTE: eml samples weird formats for recipients : list("email1, email2")
        # TODO: test this with a sample which contains recipients in format "NAME ADDRESS"
        extracted_data['email_recipients'] = []
        # list, all  recipients emails addresses in list[0]
        recipients = mail.get_all('To')
        recipients_address = recipients[0].split(",")
        for recipient in recipients_address:
            extracted_data['email_recipients'].append(dict(
                name="",
                address=recipient.strip()))

        extracted_data['email_cc'] = []
        email_cc = mail['Cc']
        if not email_cc is None:
            for address in email_cc.split(","):
                extracted_data['email_cc'].append(dict(
                    name="",
                    address=address.strip()))

        extracted_data['email_bcc'] = []
        email_bcc = mail['Bcc']
        if not email_bcc is None:
            for address in email_bcc.split(","):
                extracted_data['email_bcc'].append(dict(
                    name="",
                    address=address.strip()))

        extracted_data['email_subject'] = mail['Subject']

        extracted_data['email_attachments'] = []
        for part in mail.walk():
            if part.get_filename():
                if part.get_payload(decode=True):

                    filetype = part.get_content_type()
                    file_extension = filetype.split("/")[1]
                    filename = f"{part.get_filename()}.{file_extension}"

                    local_path = os.path.join(self.anal_dir, 'att', filename)
                    print(
                        f"INFO: Extracted attachment to {local_path}")
                    decoded_payload = part.get_payload(decode=True)
                    with open(local_path, "wb") as att_file:
                        att_file.write(decoded_payload)

                    md_5_sum = hashlib.md5(
                        part.get_payload(decode=True)).hexdigest()
                    sha_1_sum = hashlib.sha1(
                        part.get_payload(decode=True)).hexdigest()
                    sha_256_sum = hashlib.sha256(
                        part.get_payload(decode=True)).hexdigest()

                extracted_data['email_attachments'].append(dict(
                    name=filename,
                    type=filetype,
                    md5=md_5_sum,
                    sha1=sha_1_sum,
                    sha256=sha_256_sum
                ))

        print("INFO: Extracting IOCs")
        logging.info('Extracting IOCs')
        extracted_data['iocs'] = []
        ioc_regexes = self.ioc_definitions['definitions']
        for ioc_type, ioc_data in ioc_regexes.items():
            data = sorted(
                set(re.findall(ioc_data['rgx'], body, re.IGNORECASE)))
            if data:
                ioc_entry = {}
                ioc_entry.update({ioc_type: data})
                extracted_data['iocs'].append(ioc_entry)

        with open(os.path.join(self.anal_dir, 'extracted_data.json'), "w") as out_file:
            out_file.write(json.dumps(
                extracted_data, indent=2, sort_keys=False))

        with open(os.path.join(self.anal_dir, 'extracted_data.json'), "w") as out_file:
            out_file.write(json.dumps(
                extracted_data, indent=2, sort_keys=False))